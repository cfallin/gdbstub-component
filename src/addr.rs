//! Synthetic Wasm address space expected by the gdbstub Wasm
//! extensions.

use std::collections::{HashMap, hash_map::Entry};

use anyhow::{Result, bail};

use crate::api::{Debuggee, Frame, Memory, Module};

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

    pub fn from_raw(raw: u64) -> Result<Self> {
        let type_bits = (raw >> Self::TYPE_SHIFT) & Self::TYPE_MASK;
        if type_bits > 1 {
            bail!("Invalid Wasm address");
        }
        Ok(WasmAddr(raw))
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

/// Representation of the synthesized Wasm address space.
pub struct AddrSpace {
    module_ids: HashMap<u64, u32>,
    memory_ids: HashMap<u64, u32>,
    modules: Vec<Module>,
    module_bytecode: Vec<Vec<u8>>,
    memories: Vec<Memory>,
}

/// The result of a lookup in the address space.
pub enum AddrSpaceLookup<'a> {
    Module {
        module: &'a Module,
        bytecode: &'a [u8],
        offset: u32,
    },
    Memory {
        memory: &'a Memory,
        offset: u32,
    },
    Empty,
}

impl AddrSpace {
    pub fn new() -> Self {
        AddrSpace {
            module_ids: HashMap::new(),
            modules: vec![],
            module_bytecode: vec![],
            memory_ids: HashMap::new(),
            memories: vec![],
        }
    }

    fn module_id(&mut self, m: &Module) -> u32 {
        match self.module_ids.entry(m.unique_id()) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                let id = u32::try_from(self.modules.len()).unwrap();
                let bytecode = m.bytecode().unwrap_or(vec![]);
                self.module_bytecode.push(bytecode);
                self.modules.push(m.clone());
                *v.insert(id)
            }
        }
    }

    fn memory_id(&mut self, m: &Memory) -> u32 {
        match self.memory_ids.entry(m.unique_id()) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                let id = u32::try_from(self.memories.len()).unwrap();
                self.memories.push(m.clone());
                *v.insert(id)
            }
        }
    }

    /// Update/create new mappings so that all modules and instances'
    /// memories in the debuggee have mappings.
    pub fn update(&mut self, d: &Debuggee) -> Result<()> {
        for module in d.all_modules() {
            let _ = self.module_id(&module);
        }
        for instance in d.all_instances() {
            let mut idx = 0;
            loop {
                if let Ok(m) = instance.get_memory(d, idx) {
                    let _ = self.memory_id(&m);
                    idx += 1;
                } else {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Iterate over the base `WasmAddr` of every registered module.
    pub fn module_base_addrs(&self) -> impl Iterator<Item = WasmAddr> + '_ {
        (0..self.modules.len()).map(|idx| {
            WasmAddr::new(WasmAddrType::Object, u32::try_from(idx).unwrap(), 0)
        })
    }

    pub fn frame_to_pc(&self, frame: &Frame, debuggee: &Debuggee) -> WasmAddr {
        let module = frame
            .get_instance(debuggee)
            .unwrap()
            .get_module(debuggee);
        let &module_id = self
            .module_ids
            .get(&module.unique_id())
            .expect("module not found in addr space");
        let pc = frame.get_pc(debuggee).unwrap();
        WasmAddr::new(WasmAddrType::Object, module_id, pc)
    }

    /// Get the Memory or Module and offset within for a given
    /// WasmAddr.
    pub fn lookup(&self, addr: WasmAddr, d: &Debuggee) -> AddrSpaceLookup<'_> {
        let index = usize::try_from(addr.module_index()).unwrap();
        match addr.addr_type() {
            WasmAddrType::Object => {
                if index >= self.modules.len() {
                    return AddrSpaceLookup::Empty;
                }
                let bytecode = &self.module_bytecode[index];
                if addr.offset() >= u32::try_from(bytecode.len()).unwrap() {
                    return AddrSpaceLookup::Empty;
                }
                AddrSpaceLookup::Module {
                    module: &self.modules[index],
                    bytecode,
                    offset: addr.offset(),
                }
            }
            WasmAddrType::Memory => {
                if index >= self.memories.len() {
                    return AddrSpaceLookup::Empty;
                }
                let size = self.memories[index].size_bytes(d);
                if u64::from(addr.offset()) >= size {
                    return AddrSpaceLookup::Empty;
                }
                AddrSpaceLookup::Memory {
                    memory: &self.memories[index],
                    offset: addr.offset(),
                }
            }
        }
    }
}
