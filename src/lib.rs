/* TODO

- support clean connection shutdown (and re-attach)

 */

mod addr;
mod api;
mod target;

use crate::{
    addr::AddrSpace,
    api::{WasmType, WasmValue},
};
use addr::WasmAddr;
use anyhow::Result;
use futures::{FutureExt, select};
use gdbstub::{
    common::{Signal, Tid},
    conn::Connection,
    stub::{
        MultiThreadStopReason,
        state_machine::{GdbStubStateMachine, GdbStubStateMachineInner, state::Running},
    },
};
use structopt::StructOpt;
use wstd::{
    io::{AsyncRead, AsyncWrite},
    iter::AsyncIterator,
    net::{TcpListener, TcpStream},
};

#[macro_export]
macro_rules! trace {
    ($($tt:tt)*) => {
        if cfg!(feature = "trace") {
            eprintln!($($tt)*);
        }
    }
}

/// Command-line options.
#[derive(StructOpt)]
struct Options {
    /// The TCP address to listen on, in `<addr>:<port>` format.
    tcp_address: String,
}

struct Component;
api::export!(Component with_types_in api);

impl api::exports::wasmtime::debugger::debugger::Guest for Component {
    fn debug(d: &api::Debuggee, args: Vec<String>) {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Trace)
            .init();
        let options = Options::from_iter(args);
        let mut debugger = Debugger {
            debuggee: d,
            tid: Tid::new(1).unwrap(),
            options,
            running: None,
            current_pc: WasmAddr::from_raw(0).unwrap(),
            interrupt: false,
            single_stepping: false,
            frame_cache: vec![],
            addr_space: AddrSpace::new(),
        };
        wstd::runtime::block_on(async {
            debugger.run().await.expect("Debugger failed");
        });
    }
}

struct Debugger<'a> {
    debuggee: &'a api::Debuggee,
    tid: Tid,
    options: Options,
    running: Option<api::Resumption>,
    addr_space: AddrSpace,
    interrupt: bool,
    single_stepping: bool,
    current_pc: WasmAddr,
    frame_cache: Vec<api::Frame>,
}

impl<'a> Debugger<'a> {
    async fn run(&mut self) -> Result<()> {
        // Single-step once so modules are loaded and PC is at the
        // first instruction.
        self.start_single_step(api::ResumptionValue::Normal);
        self.running.as_mut().unwrap().wait().await;
        let _ = self.running.take().unwrap().result(self.debuggee)?;
        self.update_on_stop();

        let listener = TcpListener::bind(&self.options.tcp_address)
            .await
            .expect("Could not bind to TCP port");

        // Only accept one connection for the run; once the debugger
        // disconnects, we'll just continue.
        let Some(connection) = listener.incoming().next().await else {
            return Ok(());
        };

        let gdbconn = Conn::new(connection?);
        let mut stub = gdbstub::stub::GdbStub::new(gdbconn).run_state_machine(&mut *self)?;

        // Main loop.
        'mainloop: loop {
            match stub {
                GdbStubStateMachine::Idle(mut inner) => {
                    inner.borrow_conn().flush().await?;

                    // Wait for an inbound network byte.
                    let Some(byte) = inner.borrow_conn().read_byte().await? else {
                        inner.borrow_conn().flush().await?;
                        break 'mainloop;
                    };

                    stub = inner.incoming_data(self, byte)?;
                }

                GdbStubStateMachine::Running(mut inner) => {
                    inner.borrow_conn().flush().await?;

                    // Wait for either a resumption or a byte from the
                    // connection.
                    let resumption = self
                        .running
                        .as_mut()
                        .expect("In Running state, we must have a resumption future");
                    select! {
                        _ = resumption.wait().fuse() => {
                            let resumption = self.running.take().unwrap();
                            let event = resumption.result(self.debuggee)?;
                            stub = self.handle_event(event, inner).await?;
                        }
                        byte = inner.borrow_conn().read_byte().fuse() => {
                            let Some(byte) = byte? else {
                                inner.borrow_conn().flush().await?;
                                // Connection closed.
                                break 'mainloop;
                            };
                            stub = inner.incoming_data(&mut *self, byte)?;
                        }
                    }
                }
                GdbStubStateMachine::CtrlCInterrupt(mut inner) => {
                    inner.borrow_conn().flush().await?;
                    stub = inner.interrupt_handled(self, None::<MultiThreadStopReason<u64>>)?;
                }
                GdbStubStateMachine::Disconnected(mut inner) => {
                    inner.borrow_conn().flush().await?;
                    break 'mainloop;
                }
            }
        }

        Ok(())
    }

    fn start_continue(&mut self, resumption: api::ResumptionValue) {
        assert!(self.running.is_none());
        trace!("continuing");
        self.single_stepping = false;
        self.running = Some(api::Resumption::continue_(self.debuggee, resumption));
    }

    fn start_single_step(&mut self, resumption: api::ResumptionValue) {
        assert!(self.running.is_none());
        trace!("single-stepping");
        self.single_stepping = true;
        self.running = Some(api::Resumption::single_step(self.debuggee, resumption));
    }

    fn update_on_stop(&mut self) {
        self.addr_space.update(self.debuggee).unwrap();

        // Cache all frame handles for the duration of this stop.
        // The Wasm trait methods take `&self` and need access to
        // frames by depth, so we eagerly walk the full stack here.
        self.frame_cache.clear();
        let mut next = self.debuggee.exit_frames().into_iter().next();
        while let Some(f) = next {
            next = f.parent_frame(self.debuggee).unwrap();
            self.frame_cache.push(f);
        }

        if let Some(f) = self.frame_cache.first() {
            self.current_pc = self.addr_space.frame_to_pc(f, self.debuggee);
        } else {
            self.current_pc = WasmAddr::from_raw(0).unwrap();
        }
    }

    async fn handle_event<'b>(
        &mut self,
        event: api::Event,
        inner: GdbStubStateMachineInner<'b, Running, Self, Conn>,
    ) -> Result<GdbStubStateMachine<'b, Self, Conn>> {
        match event {
            api::Event::Complete => {
                trace!("Event::Complete");
                Ok(inner.report_stop(self, MultiThreadStopReason::Exited(0))?)
            }
            api::Event::Breakpoint => {
                trace!("Event::Breakpoint");
                self.update_on_stop();
                let stop_reason = if self.single_stepping {
                    MultiThreadStopReason::DoneStep
                } else {
                    MultiThreadStopReason::SwBreak(self.tid)
                };
                Ok(inner.report_stop(self, stop_reason)?)
            }
            _ => {
                trace!("other event: {event:?}");
                if self.interrupt {
                    self.interrupt = false;
                    self.update_on_stop();
                    Ok(inner.report_stop(self, MultiThreadStopReason::Signal(Signal::SIGINT))?)
                } else {
                    if self.single_stepping {
                        self.start_single_step(api::ResumptionValue::Normal);
                    } else {
                        self.start_continue(api::ResumptionValue::Normal);
                    }
                    Ok(GdbStubStateMachine::Running(inner))
                }
            }
        }
    }

    fn value_to_bytes(&self, value: WasmValue) -> Vec<u8> {
        match value.get_type() {
            WasmType::WasmI32 => value.unwrap_i32().to_le_bytes().to_vec(),
            WasmType::WasmI64 => value.unwrap_i64().to_le_bytes().to_vec(),
            WasmType::WasmF32 => value.unwrap_f32().to_le_bytes().to_vec(),
            WasmType::WasmF64 => value.unwrap_f64().to_le_bytes().to_vec(),
            WasmType::WasmV128 => value.unwrap_v128(),
            WasmType::WasmFuncref => 0u32.to_le_bytes().to_vec(),
            WasmType::WasmExnref => 0u32.to_le_bytes().to_vec(),
        }
    }
    /*
        async fn handle_command_paused(&mut self) -> Result<bool> {
            if !self.no_ack_mode {
                protocol.stream.write(&[b'+']).await?;
            }

            Ok(match cmd {
                Command::Closed => false,
                Command::QuerySupported(_features) => {
                    // Respond with library-list transfer capability and a
                    // max packet size.
                    let response = Response::Supported { packet_size: 4096 };
                    protocol.send(response).await?;
                    true
                }
                Command::StartNoAckMode => {
                    self.no_ack_mode = true;
                    protocol.send(Response::Ok).await?;
                    true
                }
                Command::EnableErrorStrings => {
                    protocol.send(Response::Ok).await?;
                    true
                }
                Command::QueryVAttachOrWaitSupported
                | Command::QueryStructuredDataPlugins
                | Command::JSON
                | Command::QueryOffsets
                | Command::X
                | Command::Symbol
                | Command::QueryModuleInfo => {
                    protocol.send(Response::Empty).await?;
                    true
                }
                Command::QueryHostInfo => {
                    protocol
                        .send(Response::HostInfo {
                            triple: "wasm32-wasip2".into(),
                            vendor: "wasmtime".into(),
                            os_type: "wasm".into(),
                            ptr_size: 4,
                        })
                        .await?;
                    true
                }
                Command::QueryProcessInfo => {
                    protocol
                        .send(Response::ProcessInfo {
                            pid: 0,
                            triple: "wasm32-wasip2".into(),
                            vendor: "wasmtime".into(),
                            os_type: "wasm".into(),
                            ptr_size: 4,
                        })
                        .await?;
                    true
                }
                Command::QueryCurrentThread => {
                    protocol.send(Response::CurrentThread { pid: 0 }).await?;
                    true
                }
                Command::SetCurrentThread { kind: _ } => {
                    protocol.send(Response::Ok).await?;
                    true
                }
                Command::QueryFirstThreadInfo => {
                    protocol.send(Response::ThreadList).await?;
                    true
                }
                Command::QueryMoreThreadInfo => {
                    protocol.send(Response::EndOfList).await?;
                    true
                }
                Command::QueryGDBServer => {
                    protocol.send(Response::Empty).await?;
                    true
                }
                Command::LaunchGDBServer => {
                    protocol.send(Response::Empty).await?;
                    true
                }
                Command::QueryThreadStopInfo | Command::QueryStopReason => {
                    protocol
                        .send(Response::StopReply(StopReply {
                            signal: 0,
                            pc: self.current_pc,
                            reason: self.stop_reason.clone(),
                        }))
                        .await?;
                    true
                }

                Command::QueryRegisterInfo(reg) => {
                    if reg == 0 {
                        protocol.send(Response::RegisterInfo("name:pc;alt-name:pc;bitsize:64;offset:0;encoding:uint;format:hex;set:General Purpose Registers;gcc:16;dwarf:16;generic:pc;".into())).await?;
                    } else {
                        protocol.send(Response::Error(45)).await?;
                    }
                    true
                }
                Command::ListThreadsInStopReply => {
                    protocol.send(Response::Ok).await?;
                    true
                }

                Command::ReadRegister(reg) => {
                    if reg == 0 {
                        protocol
                            .send(Response::RegisterValue(
                                self.current_pc.as_raw().to_le_bytes().to_vec(),
                            ))
                            .await?;
                    } else {
                        protocol.send(Response::Error(1)).await?;
                    }
                    true
                }

                Command::ReadMemory { addr, len } => {
                    let index = usize::try_from(addr.module_index()).unwrap();
                    let offset = usize::try_from(addr.offset()).unwrap();
                    let len = usize::try_from(len).unwrap();
                    match addr.addr_type() {
                        WasmAddrType::Object => {
                            if let Some(bc) = self.module_bytecode.get(index)
                                && let Some(slice) = bc.get(offset..(offset + len))
                            {
                                protocol
                                    .send(Response::MemoryContents(slice.to_vec()))
                                    .await?;
                            } else {
                                protocol.send(Response::Error(1)).await?;
                            }
                        }
                        WasmAddrType::Memory => {
                            if let Some(memory) = self.memories.get(index) {
                                let mut bytes = vec![];
                                for addr in offset..(offset + len) {
                                    bytes.push(
                                        memory
                                            .get_u8(self.debuggee, u64::try_from(addr).unwrap())
                                            .unwrap_or(0),
                                    );
                                }
                                protocol.send(Response::MemoryContents(bytes)).await?;
                            } else {
                                protocol.send(Response::Error(1)).await?;
                            }
                        }
                    }
                    true
                }
                Command::WriteMemory { addr: _, data: _ } => {
                    protocol.send(Response::Error(1)).await?;
                    true
                }
                Command::QueryMemoryRegionInfo(addr) => {
                    // Ensure all modules and memories are present.
                    for module in self.debuggee.all_modules() {
                        let _ = self.module_id(&module);
                    }
                    for instance in self.debuggee.all_instances() {
                        let mut idx = 0;
                        loop {
                            if let Ok(m) = instance.get_memory(self.debuggee, idx) {
                                let _ = self.memory_id(&m);
                                idx += 1;
                            } else {
                                break;
                            }
                        }
                    }

                    let index = usize::try_from(addr.module_index()).unwrap();
                    match addr.addr_type() {
                        WasmAddrType::Object => {
                            let len = self
                                .module_bytecode
                                .get(index)
                                .map(|bc| bc.len())
                                .unwrap_or(0);
                            trace!("memoryregioninfo query at module {index}: len 0x{len:x}");
                            protocol
                                .send(Response::MemoryRegionInfo(protocol::MemoryRegionInfo {
                                    start: WasmAddr::new(WasmAddrType::Object, addr.module_index(), 0),
                                    size: u64::try_from(len).unwrap(),
                                    permissions: "rx".into(),
                                    name: "wasm".into(),
                                }))
                                .await?;
                        }
                        WasmAddrType::Memory => {
                            let len = self
                                .memories
                                .get(index)
                                .map(|mem| mem.size_bytes(self.debuggee))
                                .unwrap_or(0);
                            trace!("memoryregioninfo query at memory {index}: len 0x{len:x}");
                            if addr.offset() < (len as u32) {
                                protocol
                                    .send(Response::MemoryRegionInfo(protocol::MemoryRegionInfo {
                                        start: WasmAddr::new(
                                            WasmAddrType::Memory,
                                            addr.module_index(),
                                            0,
                                        ),
                                        size: len,
                                        permissions: "rw".into(),
                                        name: "linear-memory".into(),
                                    }))
                                    .await?;
                            } else {
                                protocol
                                    .send(Response::MemoryRegionInfo(protocol::MemoryRegionInfo {
                                        start: WasmAddr::new(
                                            WasmAddrType::Memory,
                                            addr.module_index(),
                                            len as u32,
                                        ),
                                        size: (1 << 32) - len,
                                        permissions: "".into(),
                                        name: "empty".into(),
                                    }))
                                    .await?;
                            }
                        }
                    }
                    true
                }

                Command::Continue => {
                    self.start_continue(api::ResumptionValue::Normal);
                    true
                }
                Command::VContQuery => {
                    protocol.send(Response::VContSupported).await?;
                    true
                }
                Command::VCont(actions) => {
                    match actions.into_iter().next() {
                        Some(VContAction::Continue) | Some(VContAction::ContinueWithSignal { .. }) => {
                            self.start_continue(api::ResumptionValue::Normal)
                        }
                        Some(VContAction::Step) | Some(VContAction::StepWithSignal { .. }) => {
                            self.start_single_step(api::ResumptionValue::Normal)
                        }
                        None => {
                            protocol.send(Response::Error(1)).await?;
                        }
                    }
                    true
                }

                Command::Kill => {
                    protocol.send(Response::Empty).await?;
                    true
                }
                Command::Detach => {
                    protocol.send(Response::Empty).await?;
                    true
                }

                Command::Interrupt => {
                    self.interrupt = true;
                    true
                }

                Command::AddBreakpoint {
                    kind: _,
                    addr,
                    len: _,
                } => {
                    trace!("adding breakpoint: addr {addr:?}");
                    let module_index = usize::try_from(addr.module_index()).unwrap();
                    if let Some(module) = self.modules.get(module_index) {
                        trace!(" -> found module; offset 0x{:x}", addr.offset());
                        module.add_breakpoint(self.debuggee, addr.offset()).unwrap();
                        protocol.send(Response::Ok).await?;
                    } else {
                        protocol.send(Response::Error(1)).await?;
                    }
                    true
                }
                Command::RemoveBreakpoint {
                    kind: _,
                    addr,
                    len: _,
                } => {
                    let module_index = usize::try_from(addr.module_index()).unwrap();
                    if let Some(module) = self.modules.get(module_index) {
                        module
                            .remove_breakpoint(self.debuggee, addr.offset())
                            .unwrap();
                        protocol.send(Response::Ok).await?;
                    } else {
                        protocol.send(Response::Error(1)).await?;
                    }
                    true
                }

                Command::QueryWatchpointSupportInfo => {
                    protocol.send(Response::WatchpointSupportInfo(0)).await?;
                    true
                }

                Command::QueryLibraries => {
                    use std::fmt::Write;
                    let mut response = String::new();
                    write!(&mut response, "<library-list>").unwrap();
                    for module in self.debuggee.all_modules() {
                        let index = self.module_id(&module);
                        let addr = WasmAddr::new(WasmAddrType::Object, index, 0);
                        let addr = addr.as_raw();
                        write!(
                            &mut response,
                            "<library name=\"wasm\"><section address=\"0x{addr:x}\"/></library>"
                        )
                        .unwrap();
                    }
                    write!(&mut response, "</library-list>").unwrap();
                    protocol.send(Response::LibraryList(response)).await?;
                    true
                }

                Command::WasmCallStack => {
                    let mut pcs = vec![];
                    let mut frame = self.debuggee.exit_frames().into_iter().next();
                    while let Some(f) = frame {
                        let pc = self.frame_to_pc(&f);
                        pcs.push(pc.as_raw());
                        trace!("WasmCallStack: pc 0x{:x}", pc.as_raw());
                        frame = f.parent_frame(self.debuggee).unwrap();
                    }
                    protocol.send(Response::WasmCallStack(pcs)).await?;
                    true
                }

                Command::WasmLocal { mut frame, index } => {
                    let mut frame_handle = self.debuggee.exit_frames().into_iter().next();
                    while let Some(f) = frame_handle.as_ref()
                        && frame > 0
                    {
                        frame_handle = f.parent_frame(self.debuggee).unwrap();
                        frame -= 1;
                    }
                    if let Some(f) = frame_handle.as_ref() {
                        let index = usize::try_from(index).unwrap();
                        protocol
                            .send(Response::WasmVariable(self.value_to_bytes(
                                f.get_locals(self.debuggee).unwrap()[index].clone(),
                            )))
                            .await?;
                    } else {
                        protocol.send(Response::Error(1)).await?;
                    }
                    true
                }

                Command::WasmGlobal { mut frame, index } => {
                    let mut frame_handle = self.debuggee.exit_frames().into_iter().next();
                    while let Some(f) = frame_handle.as_ref()
                        && frame > 0
                    {
                        frame_handle = f.parent_frame(self.debuggee).unwrap();
                        frame -= 1;
                    }
                    if let Some(f) = frame_handle.as_ref() {
                        let global = f
                            .get_instance(self.debuggee)
                            .unwrap()
                            .get_global(self.debuggee, index)
                            .unwrap();
                        protocol
                            .send(Response::WasmVariable(
                                self.value_to_bytes(global.get(self.debuggee).unwrap()),
                            ))
                            .await?;
                    } else {
                        protocol.send(Response::Error(1)).await?;
                    }
                    true
                }

                Command::WasmStackValue { mut frame, index } => {
                    let mut frame_handle = self.debuggee.exit_frames().into_iter().next();
                    while let Some(f) = frame_handle.as_ref()
                        && frame > 0
                    {
                        frame_handle = f.parent_frame(self.debuggee).unwrap();
                        frame -= 1;
                    }
                    if let Some(f) = frame_handle.as_ref() {
                        let index = usize::try_from(index).unwrap();
                        protocol
                            .send(Response::WasmVariable(self.value_to_bytes(
                                f.get_stack(self.debuggee).unwrap()[index].clone(),
                            )))
                            .await?;
                    } else {
                        protocol.send(Response::Error(1)).await?;
                    }
                    true
                }

                Command::ThreadSuffixSupported | Command::QueryWorkingDir => {
                    protocol.send(Response::Empty).await?;
                    true
                }
            })
    }
        */
}

struct Conn {
    buf: Vec<u8>,
    conn: TcpStream,
}

impl Conn {
    fn new(conn: TcpStream) -> Self {
        Conn { buf: vec![], conn }
    }

    async fn flush(&mut self) -> anyhow::Result<()> {
        self.conn.write_all(&self.buf).await?;
        self.buf.clear();
        Ok(())
    }

    async fn read_byte(&mut self) -> Result<Option<u8>> {
        let mut buf = [0u8];
        let len = self.conn.read(&mut buf).await?;
        if len == 1 { Ok(Some(buf[0])) } else { Ok(None) }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        assert!(
            self.buf.is_empty(),
            "failed to async-flush before dropping connection write buffer"
        );
    }
}

impl Connection for Conn {
    type Error = anyhow::Error;

    fn write(&mut self, byte: u8) -> std::result::Result<(), Self::Error> {
        self.buf.push(byte);
        Ok(())
    }

    fn flush(&mut self) -> std::result::Result<(), Self::Error> {
        // We cannot flush synchronously; we leave this to the `async
        // fn flush` method called within the main loop. Fortunately
        // the gdbstub cannot wait for a response before returning to
        // the main loop, so we cannot introduce any deadlocks by
        // failing to flush synchronously here.
        Ok(())
    }
}
