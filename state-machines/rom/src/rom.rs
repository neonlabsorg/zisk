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
        atomic::{AtomicBool, AtomicU32},
        Arc, Mutex,
    },
    thread::JoinHandle,
};

use crate::{RomInstance, RomPlanner};
use fields::PrimeField64;
use itertools::Itertools;
use proofman_common::{AirInstance, FromTrace};
use zisk_common::{
    create_atomic_vec, BusDeviceMetrics, ComponentBuilder, CounterStats, Instance, InstanceCtx,
    Planner,
};
use zisk_core::{
    zisk_ops::ZiskOp, ZiskRom, ROM_ADDR, ROM_ADDR_MAX, ROM_ENTRY, ROM_EXIT, SRC_IMM,
};
use zisk_pil::{MainTrace, RomRomTrace, RomRomTraceRow, RomTrace};

/// The `RomSM` struct represents the ROM State Machine
pub struct RomSM {
    /// Zisk Rom
    zisk_rom: Arc<ZiskRom>,

    /// Shared biod instruction counter for monitoring ROM operations.
    bios_inst_count: Arc<Vec<AtomicU32>>,

    /// Shared program instruction counter for monitoring ROM operations.
    prog_inst_count: Arc<Vec<AtomicU32>>,
}

impl RomSM {
    /// Creates a new instance of the `RomSM` state machine.
    ///
    /// # Arguments
    /// * `zisk_rom` - The Zisk ROM representation.
    ///
    /// # Returns
    /// An `Arc`-wrapped instance of `RomSM`.
    pub fn new(zisk_rom: Arc<ZiskRom>, asm_rom_path: Option<PathBuf>) -> Arc<Self> {
        let (bios_inst_count, prog_inst_count) = if asm_rom_path.is_some() {
            (vec![], vec![])
        } else {
            (
                create_atomic_vec(((ROM_ADDR - ROM_ENTRY) as usize) >> 2), // No atomics, we can divide by 4
                create_atomic_vec((ROM_ADDR_MAX - ROM_ADDR) as usize), // Cannot be dividede by 4
            )
        };

        Arc::new(Self {
            zisk_rom,
            bios_inst_count: Arc::new(bios_inst_count),
            prog_inst_count: Arc::new(prog_inst_count),
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
            let mut multiplicity: u64;
            if inst.paddr < ROM_ADDR {
                if counter_stats.bios_inst_count.is_empty() {
                    multiplicity = 1; // If the histogram is empty, we use 1 for all pc's
                } else {
                    match calculated.load(std::sync::atomic::Ordering::Relaxed) {
                        true => {
                            multiplicity = counter_stats.bios_inst_count
                                [((inst.paddr - ROM_ENTRY) as usize) >> 2]
                                .swap(0, std::sync::atomic::Ordering::Relaxed)
                                as u64;
                        }
                        false => {
                            multiplicity = counter_stats.bios_inst_count
                                [((inst.paddr - ROM_ENTRY) as usize) >> 2]
                                .load(std::sync::atomic::Ordering::Relaxed)
                                as u64;
                        }
                    }

                    if multiplicity == 0 {
                        continue;
                    }
                    if inst.paddr == counter_stats.end_pc {
                        multiplicity += main_trace_len - counter_stats.steps % main_trace_len;
                    }
                }
            } else {
                match calculated.load(std::sync::atomic::Ordering::Relaxed) {
                    true => {
                        multiplicity = counter_stats.prog_inst_count
                            [(inst.paddr - ROM_ADDR) as usize]
                            .swap(0, std::sync::atomic::Ordering::Relaxed)
                            as u64
                    }
                    false => {
                        multiplicity = counter_stats.prog_inst_count
                            [(inst.paddr - ROM_ADDR) as usize]
                            .load(std::sync::atomic::Ordering::Relaxed)
                            as u64
                    }
                }
                if multiplicity == 0 {
                    continue;
                }
                if inst.paddr == counter_stats.end_pc {
                    multiplicity += main_trace_len - counter_stats.steps % main_trace_len;
                }
            }
            rom_trace[i].multiplicity = F::from_u64(multiplicity);
        }

        AirInstance::new_from_trace(FromTrace::new(&mut rom_trace))
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
            self.bios_inst_count.clone(),
            self.prog_inst_count.clone(),
        ))
    }
}
