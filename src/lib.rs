/* TODO

- support clean connection shutdown (and re-attach)

 */

mod api;
pub mod protocol;

use std::collections::HashMap;

use anyhow::Result;
use futures::{FutureExt, select};
use protocol::{Command, ProtocolEngine, Response};
use structopt::StructOpt;
use wstd::{io::AsyncWrite, iter::AsyncIterator, net::TcpListener};

use crate::{
    api::{Frame, Memory, Module, WasmType, WasmValue},
    protocol::{StopReason, StopReply, VContAction, WasmAddr, WasmAddrType},
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
    /// The TCP port to listen on.
    tcp_port: String,
}

struct Component;
api::export!(Component with_types_in api);

impl api::exports::wasmtime::debugger::debugger::Guest for Component {
    fn debug(d: &api::Debuggee, args: Vec<String>) {
        let options = Options::from_iter(args);
        let mut debugger = Debugger {
            debuggee: d,
            options,
            running: None,
            current_pc: WasmAddr::from_raw(0),
            stop_reason: StopReason::Breakpoint,
            interrupt: false,
            single_stepping: false,
            module_ids: HashMap::new(),
            modules: vec![],
            module_bytecode: vec![],
            memory_ids: HashMap::new(),
            memories: vec![],
            no_ack_mode: false,
        };
        wstd::runtime::block_on(async {
            debugger.run().await.expect("Debugger failed");
        });
    }
}

struct Debugger<'a> {
    debuggee: &'a api::Debuggee,
    options: Options,
    running: Option<api::Resumption>,
    module_ids: HashMap<u64, u32>,
    memory_ids: HashMap<u64, u32>,
    modules: Vec<Module>,
    module_bytecode: Vec<Vec<u8>>,
    memories: Vec<Memory>,
    interrupt: bool,
    single_stepping: bool,
    current_pc: WasmAddr,
    stop_reason: StopReason,
    no_ack_mode: bool,
}

impl<'a> Debugger<'a> {
    async fn run(&mut self) -> Result<()> {
        // Single-step once so modules are loaded and PC is at the
        // first instruction.
        self.start_single_step(api::ResumptionValue::Normal);
        self.running.as_mut().unwrap().wait().await;
        let _ = self.running.take().unwrap().result(self.debuggee)?;
        self.set_stop_reason(StopReason::Breakpoint);

        let listener = TcpListener::bind(&self.options.tcp_port)
            .await
            .expect("Could not bind to TCP port");

        while let Some(connection) = listener.incoming().next().await {
            let connection = connection?;
            let mut protocol = ProtocolEngine::new(connection);
            loop {
                if let Some(resumption) = self.running.as_mut() {
                    select! {
                        _ = resumption.wait().fuse() => {
                            let resumption = self.running.take().unwrap();
                            let event = resumption.result(self.debuggee)?;
                            if !self.handle_event(event, &mut protocol).await? {
                                return Ok(());
                            }
                        }
                        cmd = protocol.receive().fuse() => {
                            let cmd = cmd?;
                            if !self.handle_command_running(cmd, &mut protocol).await? {
                                return Ok(());
                            }
                        }
                    }
                } else {
                    let cmd = protocol.receive().await?;
                    if !self.handle_command_paused(cmd, &mut protocol).await? {
                        return Ok(());
                    }
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

    fn set_stop_reason(&mut self, reason: StopReason) {
        if let Some(frame) = self.debuggee.exit_frames().into_iter().next() {
            self.current_pc = self.frame_to_pc(&frame);
        } else {
            self.current_pc = WasmAddr::from_raw(0);
        }
        self.stop_reason = reason;
    }

    async fn handle_event(
        &mut self,
        event: api::Event,
        protocol: &mut ProtocolEngine,
    ) -> Result<bool> {
        Ok(match event {
            api::Event::Complete => {
                trace!("Event::Complete");
                self.set_stop_reason(StopReason::Exception("exited".into()));
                protocol
                    .send(Response::StopReply(StopReply {
                        signal: 0,
                        pc: self.current_pc,
                        reason: self.stop_reason.clone(),
                    }))
                    .await?;
                false
            }
            api::Event::Breakpoint => {
                trace!("Event::Breakpoint");
                if self.single_stepping {
                    self.set_stop_reason(StopReason::Trace);
                } else {
                    self.set_stop_reason(StopReason::Breakpoint);
                }
                protocol
                    .send(Response::StopReply(StopReply {
                        signal: 0,
                        pc: self.current_pc,
                        reason: self.stop_reason.clone(),
                    }))
                    .await?;
                true
            }
            _ => {
                trace!("other event: {event:?}");
                if self.interrupt {
                    self.interrupt = false;
                    self.set_stop_reason(StopReason::Signal);
                    protocol
                        .send(Response::StopReply(StopReply {
                            signal: 0,
                            pc: self.current_pc,
                            reason: self.stop_reason.clone(),
                        }))
                        .await?;
                } else {
                    if self.single_stepping {
                        self.start_single_step(api::ResumptionValue::Normal);
                    } else {
                        self.start_continue(api::ResumptionValue::Normal);
                    }
                }
                true
            }
        })
    }

    async fn handle_command_running(
        &mut self,
        cmd: Command,
        protocol: &mut ProtocolEngine,
    ) -> Result<bool> {
        Ok(match cmd {
            Command::Interrupt => {
                self.interrupt = true;
                true
            }
            Command::Closed => false,
            _ => {
                trace!("got command while running: {cmd:?}");
                protocol.send(Response::Empty).await?;
                true
            }
        })
    }

    fn module_id(&mut self, module: &Module) -> u32 {
        *self
            .module_ids
            .entry(module.unique_id())
            .or_insert_with(|| {
                let id = u32::try_from(self.modules.len()).unwrap();
                self.modules.push(module.clone());
                let bytecode = module.bytecode().unwrap();
                self.module_bytecode.push(bytecode);
                id
            })
    }

    fn memory_id(&mut self, memory: &Memory) -> u32 {
        *self
            .memory_ids
            .entry(memory.unique_id())
            .or_insert_with(|| {
                let id = u32::try_from(self.memories.len()).unwrap();
                self.memories.push(memory.clone());
                id
            })
    }

    fn frame_to_pc(&mut self, frame: &Frame) -> WasmAddr {
        let module = frame
            .get_instance(self.debuggee)
            .unwrap()
            .get_module(self.debuggee);
        let module = self.module_id(&module);
        let pc = frame.get_pc(self.debuggee).unwrap();
        WasmAddr::new(WasmAddrType::Object, module, pc)
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

    async fn handle_command_paused(
        &mut self,
        cmd: Command,
        protocol: &mut ProtocolEngine,
    ) -> Result<bool> {
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
}
