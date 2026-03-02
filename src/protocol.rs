//! gdbstub protocol support.

use anyhow::{Result, anyhow, bail};
use wstd::io::{AsyncRead, AsyncWrite};
use wstd::net::TcpStream;

/// The type of a Wasm virtual address.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WasmAddrType {
    /// Address in a 32-bit linear memory.
    Memory,
    /// Address in a `.wasm` module image.
    ///
    /// Used both for memory-read commands to fetch the Wasm binary
    /// from the gdbstub host, and software-breakpoint instructions.
    Object,
}

/// Encoded Wasm virtual address as used in the gdbstub wire protocol.
///
/// WebAssembly has distinct address spaces, one per linear
/// memory. The gdbstub protocol extended for Wasm also exposes
/// `.wasm` source bytecode as read-only address spaces served by the
/// gdbstub host. The protocol multiplexes each of these separate address
/// spaces into a single 64-bit virtual address space. This type
/// represents an address in that multiplexed space.
///
/// The address contains three fields:
/// - Type (`WasmAddrType`): either linear memory (`Memory`) or a
///   `.wasm` bytecode object (`Object`).
/// - Index: the module or linear memory for this address. Ordering is
///   defined by the host and provided in the `MemoryRegionInfo` response.
/// - Offset: the offset within the given module or linear memory.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WasmAddr(u64);

impl WasmAddr {
    const TYPE_BITS: u32 = 2;
    const MODULE_BITS: u32 = 30;
    const OFFSET_BITS: u32 = 32;

    const MODULE_SHIFT: u32 = Self::OFFSET_BITS;
    const TYPE_SHIFT: u32 = Self::OFFSET_BITS + Self::MODULE_BITS;

    const TYPE_MASK: u64 = (1u64 << Self::TYPE_BITS) - 1;
    const MODULE_MASK: u64 = (1u64 << Self::MODULE_BITS) - 1;
    const OFFSET_MASK: u64 = (1u64 << Self::OFFSET_BITS) - 1;

    pub fn from_raw(raw: u64) -> Self {
        let type_bits = (raw >> Self::TYPE_SHIFT) & Self::TYPE_MASK;
        assert!(type_bits <= 1);
        WasmAddr(raw)
    }

    pub fn as_raw(self) -> u64 {
        self.0
    }

    pub fn new(addr_type: WasmAddrType, module_index: u32, offset: u32) -> Self {
        assert_eq!(module_index >> Self::MODULE_BITS, 0);
        let type_bits: u64 = match addr_type {
            WasmAddrType::Memory => 0,
            WasmAddrType::Object => 1,
        };
        WasmAddr(
            (type_bits << Self::TYPE_SHIFT)
                | ((module_index as u64) << Self::MODULE_SHIFT)
                | (offset as u64),
        )
    }

    pub fn addr_type(self) -> WasmAddrType {
        match (self.0 >> Self::TYPE_SHIFT) & Self::TYPE_MASK {
            0 => WasmAddrType::Memory,
            1 => WasmAddrType::Object,
            _ => panic!("WasmAddr: invalid type bits"),
        }
    }

    pub fn module_index(self) -> u32 {
        ((self.0 >> Self::MODULE_SHIFT) & Self::MODULE_MASK) as u32
    }

    pub fn offset(self) -> u32 {
        (self.0 & Self::OFFSET_MASK) as u32
    }
}

impl std::fmt::Display for WasmAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let type_str = match self.addr_type() {
            WasmAddrType::Memory => "Memory",
            WasmAddrType::Object => "Object",
        };
        write!(
            f,
            "{}(module={}, offset={:#x})",
            type_str,
            self.module_index(),
            self.offset()
        )
    }
}

impl std::fmt::Debug for WasmAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WasmAddr({self})")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    Software,
    WriteWatchpoint,
    ReadWatchpoint,
    ReadWriteWatchpoint,
}

#[derive(Debug, Clone)]
pub enum VContAction {
    Continue,
    Step,
    ContinueWithSignal { signal: u8 },
    StepWithSignal { signal: u8 },
}

#[derive(Debug, Clone)]
pub enum StopReason {
    Breakpoint,
    Trace,
    Signal,
    Exception(String),
}

#[derive(Debug, Clone)]
pub struct StopReply {
    pub signal: u8,
    pub pc: WasmAddr,
    pub reason: StopReason,
}

#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub start: WasmAddr,
    pub size: u64,
    pub permissions: String,
    pub name: String,
}

#[derive(Debug)]
pub enum Command {
    Closed,

    QuerySupported(Vec<String>),
    StartNoAckMode,
    EnableErrorStrings,
    ThreadSuffixSupported,
    ListThreadsInStopReply,

    QueryStopReason,
    QueryHostInfo,
    QueryProcessInfo,
    QueryCurrentThread,
    SetCurrentThread {
        kind: char,
    },
    QueryFirstThreadInfo,
    QueryMoreThreadInfo,
    QueryThreadStopInfo,

    QueryGDBServer,
    LaunchGDBServer,

    QueryRegisterInfo(u32),
    ReadRegister(u32),

    ReadMemory {
        addr: WasmAddr,
        len: u64,
    },
    WriteMemory {
        addr: WasmAddr,
        data: Vec<u8>,
    },
    QueryMemoryRegionInfo(WasmAddr),

    Continue,
    VContQuery,
    VCont(Vec<VContAction>),
    Kill,
    Detach,
    Interrupt,

    AddBreakpoint {
        kind: BreakpointKind,
        addr: WasmAddr,
        len: u64,
    },
    RemoveBreakpoint {
        kind: BreakpointKind,
        addr: WasmAddr,
        len: u64,
    },
    QueryWatchpointSupportInfo,

    QueryVAttachOrWaitSupported,

    QueryStructuredDataPlugins,

    QueryLibraries,
    QueryWorkingDir,

    WasmCallStack,
    WasmLocal {
        frame: u32,
        index: u32,
    },
    WasmGlobal {
        frame: u32,
        index: u32,
    },
    WasmStackValue {
        frame: u32,
        index: u32,
    },

    // Unsupported
    JSON,
    QueryOffsets,
    X,
    Symbol,
    QueryModuleInfo,
}

#[derive(Debug)]
pub enum Response {
    Ok,
    Error(u8),
    Empty,

    StopReply(StopReply),
    ProcessExited(u8),

    Supported {
        packet_size: usize,
    },

    CurrentThread {
        pid: u64,
    },
    ThreadList,
    EndOfList,

    HostInfo {
        triple: String,
        vendor: String,
        os_type: String,
        ptr_size: u8,
    },
    ProcessInfo {
        pid: u64,
        triple: String,
        vendor: String,
        os_type: String,
        ptr_size: u8,
    },

    RegisterInfo(String),
    RegisterInfoEnd,
    RegisterValue(Vec<u8>),

    MemoryContents(Vec<u8>),
    MemoryRegionInfo(MemoryRegionInfo),

    VContSupported,

    LibraryList(String),
    WorkingDir(String),

    WasmCallStack(Vec<u64>),
    WasmVariable(Vec<u8>),

    WatchpointSupportInfo(u32),
}

impl Response {
    fn to_payload(&self) -> String {
        match self {
            Response::Ok => "OK".into(),
            Response::Error(n) => format!("E{:02x}", n),
            Response::Empty => String::new(),

            Response::StopReply(r) => format_stop_reply(r),
            Response::ProcessExited(status) => format!("W{:02x}", status),

            Response::Supported { packet_size } => {
                format!("qXfer:libraries:read+;PacketSize={:x};", packet_size)
            }

            Response::CurrentThread { pid } => format!("QCp{:x}.0", pid),
            Response::ThreadList => "m0".into(),
            Response::EndOfList => "l".into(),

            Response::HostInfo {
                triple,
                vendor,
                os_type,
                ptr_size,
            } => {
                let triple_hex = hex_encode(triple.as_bytes());
                format!(
                    "vendor:{};ostype:{};arch:wasm32;triple:{};endian:little;ptrsize:{};",
                    vendor, os_type, triple_hex, ptr_size
                )
            }
            Response::ProcessInfo {
                pid,
                triple,
                vendor,
                os_type,
                ptr_size,
            } => {
                let triple_hex = hex_encode(triple.as_bytes());
                format!(
                    "pid:{:x};parent-pid:{:x};vendor:{};ostype:{};arch:wasm32;\
                     triple:{};endian:little;ptrsize:{};",
                    pid, pid, vendor, os_type, triple_hex, ptr_size
                )
            }

            Response::RegisterInfo(s) => s.clone(),
            Response::RegisterInfoEnd => "E45".into(),
            Response::RegisterValue(bytes) => hex_encode(bytes),

            Response::MemoryContents(bytes) => hex_encode(bytes),
            Response::MemoryRegionInfo(info) => {
                let name_hex = hex_encode(info.name.as_bytes());
                format!(
                    "start:{:x};size:{:x};permissions:{};name:{};",
                    info.start.as_raw(),
                    info.size,
                    info.permissions,
                    name_hex
                )
            }

            Response::VContSupported => "vCont;c;C;s;S;".into(),

            Response::LibraryList(xml) => format!("l{}", xml),
            Response::WorkingDir(dir) => dir.clone(),

            Response::WasmCallStack(frames) => {
                let mut out = String::with_capacity(frames.len() * 16);
                for &pc in frames {
                    out.push_str(&encode_le_u64(pc));
                }
                out
            }
            Response::WasmVariable(bytes) => hex_encode(bytes),

            Response::WatchpointSupportInfo(n) => format!("num:{};", n),
        }
    }
}

fn format_stop_reply(r: &StopReply) -> String {
    let mut s = format!("T{:02x}thread:0;name:nobody;", r.signal);

    let pc_le = encode_le_u64(r.pc.as_raw());
    s.push_str(&format!("thread-pcs:{:x};00:{};", r.pc.as_raw(), pc_le));

    match &r.reason {
        StopReason::Breakpoint => s.push_str("reason:breakpoint;"),
        StopReason::Trace => s.push_str("reason:trace;"),
        StopReason::Signal => s.push_str("reason:signal;"),
        StopReason::Exception(msg) => {
            let desc = hex_encode(msg.as_bytes());
            s.push_str(&format!("reason:exception;description:{};", desc));
        }
    }
    s
}

pub struct ProtocolEngine {
    pub stream: TcpStream,
    // For cancel-safety, we keep a buffer of bytes; this will
    // normally be empty between reading inbound packets, but may
    // contain read-but-not-processed bytes if a future was canceled.
    replay: Vec<u8>,
    buf: Vec<u8>,
}

#[derive(Clone, Debug)]
enum RawReadResult {
    Bytes(Vec<u8>),
    OOBInterrupt,
    Closed,
}

impl ProtocolEngine {
    pub fn new(stream: TcpStream) -> Self {
        ProtocolEngine {
            stream,
            replay: vec![],
            buf: vec![],
        }
    }

    /// Read one byte. Returns `None` for a closed connection.
    async fn read_byte(&mut self) -> Result<Option<u8>> {
        if !self.replay.is_empty() {
            return Ok(self.replay.pop());
        }

        let mut buf = [0u8; 1];
        let n = self
            .stream
            .read(&mut buf)
            .await
            .map_err(|e| anyhow!("read: {e}"))?;
        if n == 0 {
            Ok(None)
        } else {
            let byte = buf[0];
            // Save byte for replay if command-parsing future is
            // canceled.
            self.buf.push(byte);
            Ok(Some(byte))
        }
    }

    /// Commit to the previously-read bytes being used.
    fn commit_bytes(&mut self) {
        self.buf.clear();
        self.replay.clear();
    }

    fn start_parse(&mut self) {
        self.replay = std::mem::take(&mut self.buf);
        self.replay.reverse(); // So we can pop off the back.
    }

    /// Write raw bytes to the stream.
    async fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read a command packet.
    async fn read_packet_raw(&mut self) -> Result<RawReadResult> {
        let result = self.read_packet_raw_impl().await;
        self.commit_bytes();
        result
    }

    /// Packet-read implementation.
    async fn read_packet_raw_impl(&mut self) -> Result<RawReadResult> {
        self.start_parse();
        loop {
            let Some(b) = self.read_byte().await? else {
                return Ok(RawReadResult::Closed);
            };

            // Out-of-band interrupt byte.
            if b == 0x03 {
                return Ok(RawReadResult::OOBInterrupt);
            }

            // Skip any non-`$` bytes (stray data before packet start).
            if b != b'$' {
                continue;
            }

            // Read the payload, computing a running checksum, until `#`.
            let mut payload = Vec::with_capacity(64);
            let mut running_sum: u8 = 0;
            loop {
                let Some(b) = self.read_byte().await? else {
                    return Ok(RawReadResult::Closed);
                };
                if b == b'#' {
                    break;
                }
                payload.push(b);
                running_sum = running_sum.wrapping_add(b);
            }

            // Read and validate the two-hex-digit checksum after `#`.
            let Some(hi) = self.read_byte().await? else {
                return Ok(RawReadResult::Closed);
            };
            let Some(lo) = self.read_byte().await? else {
                return Ok(RawReadResult::Closed);
            };
            let received_sum = u8::from_str_radix(str::from_utf8(&[hi, lo])?, 16)?;
            if running_sum != received_sum {
                bail!(
                    "checksum mismatch: computed {:#04x}, received {:#04x}",
                    running_sum,
                    received_sum
                );
            }

            return Ok(RawReadResult::Bytes(payload));
        }
    }

    /// Receive the next [`Command`].
    pub async fn receive(&mut self) -> Result<Command> {
        match self.read_packet_raw().await? {
            RawReadResult::Closed => Ok(Command::Closed),
            RawReadResult::OOBInterrupt => Ok(Command::Interrupt),
            RawReadResult::Bytes(payload) => parse_command(&payload),
        }
    }

    /// Send a [`Response`].
    pub async fn send(&mut self, response: Response) -> Result<()> {
        let payload = response.to_payload();
        let checksum: u8 = payload.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
        let packet = format!("${}#{:02x}", payload, checksum);
        self.write_raw(packet.as_bytes()).await
    }
}

fn parse_command(payload: &[u8]) -> Result<Command> {
    crate::trace!("parse command: {}", str::from_utf8(payload).unwrap());
    if payload.is_empty() {
        bail!("empty payload");
    }
    let text = std::str::from_utf8(payload)?;
    Ok(match payload[0] {
        b'?' => Command::QueryStopReason,
        b'c' => Command::Continue,
        b'k' => Command::Kill,
        b'D' => Command::Detach,
        b'H' => parse_h(text)?,
        b'p' => parse_p(text),
        b'm' => parse_m(text)?,
        b'M' => parse_big_m(text)?,
        b'Z' => parse_zz(text, true)?,
        b'z' => parse_zz(text, false)?,
        b'q' => parse_q(&text[1..])?,
        b'Q' => parse_big_q(&text[1..])?,
        b'v' => parse_v(&text[1..])?,
        b'j' => Command::JSON,
        b'x' => Command::X,
        b'_' => Command::X,
        b => bail!("unrecognized packet byte 0x{:02x}", b),
    })
}

fn parse_h(s: &str) -> Result<Command> {
    let kind = s[1..]
        .chars()
        .next()
        .ok_or_else(|| anyhow!("H packet: missing kind byte"))?;
    Ok(Command::SetCurrentThread { kind })
}

fn parse_p(s: &str) -> Command {
    let n = u32::from_str_radix(s[1..].trim(), 16).unwrap_or(0);
    Command::ReadRegister(n)
}

fn parse_m(s: &str) -> Result<Command> {
    let s = &s[1..]; // skip 'm'
    let (addr_s, len_s) = s
        .split_once(',')
        .ok_or_else(|| anyhow!("m packet: missing comma"))?;
    let addr = WasmAddr::from_raw(u64::from_str_radix(addr_s, 16)?);
    let len = u64::from_str_radix(len_s, 16)?;
    Ok(Command::ReadMemory { addr, len })
}

fn parse_big_m(s: &str) -> Result<Command> {
    let s = &s[1..]; // skip 'M'
    if let Some((header, hex_data)) = s.split_once(':')
        && let Some((addr_s, _len_s)) = header.split_once(',')
    {
        let addr = WasmAddr::from_raw(u64::from_str_radix(addr_s, 16)?);
        let data = hex_decode(hex_data)?;
        return Ok(Command::WriteMemory { addr, data });
    }
    bail!("M packet: invalid format")
}

fn parse_zz(s: &str, add: bool) -> Result<Command> {
    let rest = &s[1..]; // skip 'Z' or 'z'
    let parts: Vec<&str> = rest.splitn(3, ',').collect();
    if parts.len() != 3 {
        bail!(
            "Z/z packet: expected 3 comma-separated fields, got {}",
            parts.len()
        );
    }
    let kind = match parts[0] {
        "0" => BreakpointKind::Software,
        "2" => BreakpointKind::WriteWatchpoint,
        "3" => BreakpointKind::ReadWatchpoint,
        "4" => BreakpointKind::ReadWriteWatchpoint,
        t => bail!("Z/z packet: unknown breakpoint type {:?}", t),
    };
    let addr = WasmAddr::from_raw(u64::from_str_radix(parts[1], 16)?);
    let len = u64::from_str_radix(parts[2], 16)?;
    Ok(if add {
        Command::AddBreakpoint { kind, addr, len }
    } else {
        Command::RemoveBreakpoint { kind, addr, len }
    })
}

fn parse_q(s: &str) -> Result<Command> {
    let (name, args) = split_name_args(s);
    Ok(match name {
        "Supported" => {
            let features = if args.is_empty() {
                vec![]
            } else {
                args.split(';').map(|f| f.to_owned()).collect()
            };
            Command::QuerySupported(features)
        }
        "C" => Command::QueryCurrentThread,
        "HostInfo" => Command::QueryHostInfo,
        "ProcessInfo" => Command::QueryProcessInfo,
        "fThreadInfo" => Command::QueryFirstThreadInfo,
        "sThreadInfo" => Command::QueryMoreThreadInfo,
        "GetWorkingDir" => Command::QueryWorkingDir,
        "WatchpointSupportInfo" => Command::QueryWatchpointSupportInfo,
        "Xfer" => parse_qxfer(args)?,
        "MemoryRegionInfo" => {
            let addr = WasmAddr::from_raw(u64::from_str_radix(args, 16)?);
            Command::QueryMemoryRegionInfo(addr)
        }
        "WasmCallStack" => Command::WasmCallStack,
        "WasmLocal" => {
            parse_wasm_frame_index(args, |frame, index| Command::WasmLocal { frame, index })?
        }
        "WasmGlobal" => {
            parse_wasm_frame_index(args, |frame, index| Command::WasmGlobal { frame, index })?
        }
        "WasmStackValue" => parse_wasm_frame_index(args, |frame, index| Command::WasmStackValue {
            frame,
            index,
        })?,
        _ if name.starts_with("RegisterInfo") => {
            let idx_str = &name["RegisterInfo".len()..];
            let n = u32::from_str_radix(idx_str, 16).unwrap_or(u32::MAX);
            Command::QueryRegisterInfo(n)
        }
        _ if name.starts_with("ThreadStopInfo") => Command::QueryThreadStopInfo,
        "QueryGDBServer" => Command::QueryGDBServer,
        _ if name.starts_with("LaunchGDBServer") => Command::LaunchGDBServer,
        "VAttachOrWaitSupported" => Command::QueryVAttachOrWaitSupported,
        "StructuredDataPlugins" => Command::QueryStructuredDataPlugins,
        "Offsets" => Command::QueryOffsets,
        "Symbol" => Command::Symbol,
        "ModuleInfo" => Command::QueryModuleInfo,
        _ => bail!("unrecognized q packet {:?}", name),
    })
}

fn parse_big_q(s: &str) -> Result<Command> {
    let (name, _args) = split_name_args(s);
    Ok(match name {
        "StartNoAckMode" => Command::StartNoAckMode,
        "EnableErrorStrings" => Command::EnableErrorStrings,
        "ThreadSuffixSupported" => Command::ThreadSuffixSupported,
        "ListThreadsInStopReply" => Command::ListThreadsInStopReply,
        _ => bail!("unrecognized Q packet {:?}", name),
    })
}

fn parse_v(s: &str) -> Result<Command> {
    if s == "Cont?" {
        return Ok(Command::VContQuery);
    }
    if let Some(rest) = s.strip_prefix("Cont;") {
        return Ok(Command::VCont(parse_vcont_actions(rest)));
    }
    bail!("unrecognized v packet {:?}", s)
}

fn parse_qxfer(args: &str) -> Result<Command> {
    if args.starts_with("libraries:read:") {
        Ok(Command::QueryLibraries)
    } else {
        bail!("unrecognized qXfer target {:?}", args)
    }
}

fn parse_wasm_frame_index<F>(args: &str, mk: F) -> Result<Command>
where
    F: Fn(u32, u32) -> Command,
{
    let (frame_s, index_s) = args
        .split_once(';')
        .ok_or_else(|| anyhow!("Wasm frame packet: missing semicolon"))?;
    let frame = frame_s.parse()?;
    let index = index_s.parse()?;
    Ok(mk(frame, index))
}

fn parse_vcont_actions(s: &str) -> Vec<VContAction> {
    s.split(';')
        .filter(|p| !p.is_empty())
        .filter_map(|part| {
            // Each part is `<action>[:<tid>]`; strip the optional tid.
            let action_s = part.split_once(':').map_or(part, |(a, _)| a);
            match action_s {
                "c" => Some(VContAction::Continue),
                "s" => Some(VContAction::Step),
                _ if action_s.starts_with('C') => {
                    let sig = u8::from_str_radix(&action_s[1..], 16).ok()?;
                    Some(VContAction::ContinueWithSignal { signal: sig })
                }
                _ if action_s.starts_with('S') => {
                    let sig = u8::from_str_radix(&action_s[1..], 16).ok()?;
                    Some(VContAction::StepWithSignal { signal: sig })
                }
                _ => None,
            }
        })
        .collect()
}

fn split_name_args(s: &str) -> (&str, &str) {
    match s.find(':') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|bytes| str::from_utf8(bytes).ok())
        .map(|bytes| Ok(u8::from_str_radix(bytes, 16)?))
        .collect()
}

fn encode_le_u64(val: u64) -> String {
    hex_encode(&val.to_le_bytes())
}
