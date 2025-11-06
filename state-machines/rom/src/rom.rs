//! The `RomSM` module implements the ROM State Machine,
//! directly managing the ROM execution process, generating traces, and computing custom traces.
//!
//! Key components of this module include:
//! - The `RomSM` struct, which represents the ROM State Machine and encapsulates ROM-related
//!   operations.
//! - Methods for proving instances and computing traces from the ROM data.
//! - `ComponentBuilder` trait implementations for creating counters, planners, and input
//!   collectors.

use std::{
    path::PathBuf,
    sync::{
        atomic::AtomicBool,
        Arc,
    }
};

use crate::{RomInstance, RomPlanner};
use fields::PrimeField64;
use itertools::Itertools;
use proofman_common::{AirInstance, FromTrace};
use zisk_common::{
    BusDeviceMetrics, ComponentBuilder, CounterStats, Instance, InstanceCtx,
    Planner,
};
use zisk_core::{
    zisk_ops::ZiskOp, ZiskRom, SRC_IMM,
};
use zisk_pil::{MainTrace, RomRomTrace, RomRomTraceRow, RomTrace};

/// The `RomSM` struct represents the ROM State Machine
pub struct RomSM {
    /// Zisk Rom
    zisk_rom: Arc<ZiskRom>,

    pc_counters: CounterStats
}

impl RomSM {
    /// Creates a new instance of the `RomSM` state machine.
    ///
    /// # Arguments
    /// * `zisk_rom` - The Zisk ROM representation.
    ///
    /// # Returns
    /// An `Arc`-wrapped instance of `RomSM`.
    pub fn new(zisk_rom: Arc<ZiskRom>) -> Arc<Self> {
        let pc_counters = CounterStats::new_inited(zisk_rom.pc_iter());
        Arc::new(Self {
            zisk_rom,
            pc_counters
        })
    }

    /// Computes the witness for the provided plan using the given ROM.
    ///
    /// # Arguments
    /// * `rom` - Reference to the Zisk ROM.
    /// * `plan` - The execution plan for computing the witness.
    ///
    /// # Returns
    /// An `AirInstance` containing the computed witness trace data.
    pub fn compute_witness<F: PrimeField64>(
        rom: &ZiskRom,
        counter_stats: &CounterStats,
        calculated: &AtomicBool,
        trace_buffer: Vec<F>,
    ) -> AirInstance<F> {
        let mut rom_trace = RomTrace::new_from_vec_zeroes(trace_buffer);

        let main_trace_len = MainTrace::<F>::NUM_ROWS as u64;

        tracing::info!("··· Creating Rom instance [{} rows]", rom_trace.num_rows());

        // For every instruction in the rom, fill its corresponding ROM trace
        for (i, pc) in rom.pc_iter().sorted().enumerate() {
            // Get the Zisk instruction
            let inst = rom.get_instruction(pc);

            // Calculate the multiplicity, i.e. the number of times this pc is used in this
            // execution
            let mut multiplicity = 
                match calculated.load(std::sync::atomic::Ordering::Relaxed) {
                    true => counter_stats.inst_count[&pc].swap(0, std::sync::atomic::Ordering::Relaxed),
                    false => counter_stats.inst_count[&pc].load(std::sync::atomic::Ordering::Relaxed),
                } as u64;

            if multiplicity == 0 {
                continue;
            }

            if inst.paddr == counter_stats.end_pc {
                multiplicity += main_trace_len - counter_stats.steps % main_trace_len;
            }

            rom_trace[i].multiplicity = F::from_u64(multiplicity);
        }

        AirInstance::new_from_trace(FromTrace::new(&mut rom_trace))
    }

    /// Computes the ROM trace based on the ROM instructions.
    ///
    /// # Arguments
    /// * `rom` - Reference to the Zisk ROM.
    /// * `rom_custom_trace` - Reference to the custom ROM trace.
    pub fn compute_trace_rom<F: PrimeField64>(rom: &ZiskRom, rom_custom_trace: &mut RomRomTrace<F>) {
        let mut inst_count = 0;
        // For every instruction in the rom, fill its corresponding ROM trace
        for (i, key) in rom.pc_iter().sorted().enumerate() {
            inst_count += 1;

            // Get the Zisk instruction
            let inst = &rom.get_instruction(key);

            // Convert the i64 offsets to F
            let jmp_offset1 = if inst.jmp_offset1 >= 0 {
                F::from_u64(inst.jmp_offset1 as u64)
            } else {
                F::neg(F::from_u64((-inst.jmp_offset1) as u64))
            };
            let jmp_offset2 = if inst.jmp_offset2 >= 0 {
                F::from_u64(inst.jmp_offset2 as u64)
            } else {
                F::neg(F::from_u64((-inst.jmp_offset2) as u64))
            };
            let store_offset = if inst.store_offset >= 0 {
                F::from_u64(inst.store_offset as u64)
            } else {
                F::neg(F::from_u64((-inst.store_offset) as u64))
            };
            let a_offset_imm0 = if inst.a_offset_imm0 as i64 >= 0 {
                F::from_u64(inst.a_offset_imm0)
            } else {
                F::neg(F::from_u64((-(inst.a_offset_imm0 as i64)) as u64))
            };
            let b_offset_imm0 = if inst.b_offset_imm0 as i64 >= 0 {
                F::from_u64(inst.b_offset_imm0)
            } else {
                F::neg(F::from_u64((-(inst.b_offset_imm0 as i64)) as u64))
            };

            // Fill the rom trace row fields
            rom_custom_trace[i].line = F::from_u64(inst.paddr); // TODO: unify names: pc, paddr, line
            rom_custom_trace[i].a_offset_imm0 = a_offset_imm0;
            rom_custom_trace[i].a_imm1 =
                F::from_u64(if inst.a_src == SRC_IMM { inst.a_use_sp_imm1 } else { 0 });
            rom_custom_trace[i].b_offset_imm0 = b_offset_imm0;
            rom_custom_trace[i].b_imm1 =
                F::from_u64(if inst.b_src == SRC_IMM { inst.b_use_sp_imm1 } else { 0 });
            rom_custom_trace[i].ind_width = F::from_u64(inst.ind_width);
            // IMPORTANT: the opcodes fcall, fcall_get, and fcall_param are really a variant
            // of the copyb, use to get free-input information
            rom_custom_trace[i].op = if inst.op == ZiskOp::Fcall.code()
                || inst.op == ZiskOp::FcallGet.code()
                || inst.op == ZiskOp::FcallParam.code()
            {
                F::from_u8(ZiskOp::CopyB.code())
            } else {
                F::from_u8(inst.op)
            };
            rom_custom_trace[i].store_offset = store_offset;
            rom_custom_trace[i].jmp_offset1 = jmp_offset1;
            rom_custom_trace[i].jmp_offset2 = jmp_offset2;
            rom_custom_trace[i].flags = F::from_u64(inst.get_flags());
        }

        // Padd with zeroes
        for i in inst_count..rom_custom_trace.num_rows() {
            rom_custom_trace[i] = RomRomTraceRow::default();
        }
    }

    /// Computes a custom trace ROM from the given ELF file.
    ///
    /// # Arguments
    /// * `rom_path` - The path to the ELF file.
    /// * `rom_custom_trace` - Reference to the custom ROM trace.
    pub fn compute_custom_trace_rom<F: PrimeField64>(
        rom_path: PathBuf,
        rom_custom_trace: &mut RomRomTrace<F>,
    ) {
        // Get the ELF file path as a string
        tracing::info!("Computing custom trace ROM");
        let rom = ZiskRom::load_from_path(rom_path).0;

        Self::compute_trace_rom(&rom, rom_custom_trace);
    }
}

impl<F: PrimeField64> ComponentBuilder<F> for RomSM {
    /// Builds and returns a new counter for monitoring ROM operations.
    ///
    /// # Returns
    /// A boxed implementation of `RomCounter`.
    fn build_counter(&self) -> Option<Box<dyn BusDeviceMetrics>> {
        None
    }

    /// Builds a planner for ROM-related instances.
    ///
    /// # Returns
    /// A boxed implementation of `RomPlanner`.
    fn build_planner(&self) -> Box<dyn Planner> {
        Box::new(RomPlanner)
    }

    /// Builds an instance of the ROM state machine.
    ///
    /// # Arguments
    /// * `ictx` - The context of the instance, containing the plan and its associated
    ///
    /// # Returns
    /// A boxed implementation of `RomInstance`.
    fn build_instance(&self, ictx: InstanceCtx) -> Box<dyn Instance<F>> {
        Box::new(RomInstance::new(
            self.zisk_rom.clone(),
            ictx,
            CounterStats::copy_counters(&self.pc_counters)
        ))
    }
}
