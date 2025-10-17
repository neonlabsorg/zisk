//! The `WitnessLib` library defines the core witness computation framework,
//! integrating the ZisK execution environment with state machines and witness components.
//!
//! This module leverages `WitnessLibrary` to orchestrate the setup of state machines,
//! program conversion, and execution pipelines to generate required witnesses.

use executor::{StateMachines, StaticSMBundle, ZiskExecutor};
use fields::{Goldilocks, PrimeField64};
use pil_std_lib::Std;
use proofman::register_std;
use std::{any::Any, path::PathBuf, sync::Arc};
use witness::{WitnessLibrary, WitnessManager};
use zisk_core::CHUNK_SIZE;
use zisk_pil::{
    ARITH_AIR_IDS, ARITH_EQ_384_AIR_IDS, ARITH_EQ_AIR_IDS, BINARY_ADD_AIR_IDS, BINARY_AIR_IDS,
    BINARY_EXTENSION_AIR_IDS, INPUT_DATA_AIR_IDS, KECCAKF_AIR_IDS, MEM_AIR_IDS, MEM_ALIGN_AIR_IDS,
    MEM_ALIGN_BYTE_AIR_IDS, MEM_ALIGN_READ_BYTE_AIR_IDS, MEM_ALIGN_WRITE_BYTE_AIR_IDS, ROM_AIR_IDS,
    ROM_DATA_AIR_IDS, SHA_256_F_AIR_IDS, ZISK_AIRGROUP_ID,
};

use precomp_arith_eq::ArithEqManager;
use precomp_arith_eq_384::ArithEq384Manager;
use precomp_keccakf::KeccakfManager;
use precomp_sha256f::Sha256fManager;
use sm_accounts::{init::AccountsInitSM, poseidon::PoseidonPermuter, AccountsSMBundle};
use sm_arith::ArithSM;
use sm_binary::BinarySM;
use sm_mem::{Mem, MemInitValuesSlot};
use sm_rom::RomSM;
use zisk_core::ZiskRom;

pub struct WitnessLib<F: PrimeField64> {
    elf_path: PathBuf,
    executor: Option<Arc<ZiskExecutor<F>>>,
    chunk_size: u64,
    world_rank: i32,
    local_rank: i32,
    base_port: Option<u16>,
    unlock_mapped_memory: bool,
    shared_tables: bool,
    poseidon_permuter: PoseidonPermuter<F>
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
fn init_library(
    verbose_mode: proofman_common::VerboseMode,
    elf_path: PathBuf,
    world_rank: Option<i32>,
    local_rank: Option<i32>,
    base_port: Option<u16>,
    unlock_mapped_memory: bool,
    shared_tables: bool,
) -> Result<Box<dyn witness::WitnessLibrary<Goldilocks>>, Box<dyn std::error::Error>> {
    proofman_common::initialize_logger(verbose_mode, world_rank);

    let chunk_size = CHUNK_SIZE;

    let result = Box::new(WitnessLib {
        elf_path,
        executor: None,
        chunk_size,
        world_rank: world_rank.unwrap_or(0),
        local_rank: local_rank.unwrap_or(0),
        base_port,
        unlock_mapped_memory,
        shared_tables,
        poseidon_permuter: PoseidonPermuter::<Goldilocks>::default()
    });

    Ok(result)
}

impl<F: PrimeField64> WitnessLibrary<F> for WitnessLib<F> {
    /// Registers the witness components and initializes the execution pipeline.
    ///
    /// # Arguments
    /// * `wcm` - An `Arc`-wrapped `WitnessManager` instance that orchestrates witness generation.
    ///
    /// This method performs the following steps:
    /// 1. Converts a RISC-V program to the ZisK ROM format using `Riscv2zisk`.
    /// 2. Initializes core and secondary state machines for witness generation.
    /// 3. Registers the state machines with the `ZiskExecutor`.
    /// 4. Registers the `ZiskExecutor` as a component in the `WitnessManager`.
    ///
    /// # Panics
    /// Panics if the `Riscv2zisk` conversion fails or if required paths cannot be resolved.
    fn register_witness(&mut self, wcm: &WitnessManager<F>) {
        let (zisk_rom, accounts) = ZiskRom::load_from_path(self.elf_path.clone());
        let zisk_rom = Arc::new(zisk_rom);

        // Step 3: Initialize the secondary state machines
        let std = Std::new(wcm.get_pctx(), wcm.get_sctx(), self.shared_tables);
        register_std(wcm, &std);

        let rom_sm = RomSM::new(zisk_rom.clone());
        let binary_sm = BinarySM::new(std.clone());
        let arith_sm = ArithSM::new(std.clone());
        let mem_init_slot = MemInitValuesSlot::new();
        let mem_sm = Mem::new(std.clone(), mem_init_slot.clone());

        // Step 4: Initialize the precompiles state machines
        let keccakf_sm = KeccakfManager::new(wcm.get_sctx(), std.clone());
        let sha256f_sm = Sha256fManager::new(std.clone());
        let arith_eq_sm = ArithEqManager::new(std.clone());
        let arith_eq_384_sm = ArithEq384Manager::new(std.clone());

        let mem_instances = vec![
            (ZISK_AIRGROUP_ID, MEM_AIR_IDS[0]),
            (ZISK_AIRGROUP_ID, ROM_DATA_AIR_IDS[0]),
            (ZISK_AIRGROUP_ID, INPUT_DATA_AIR_IDS[0]),
            (ZISK_AIRGROUP_ID, MEM_ALIGN_AIR_IDS[0]),
            (ZISK_AIRGROUP_ID, MEM_ALIGN_BYTE_AIR_IDS[0]),
            (ZISK_AIRGROUP_ID, MEM_ALIGN_WRITE_BYTE_AIR_IDS[0]),
            (ZISK_AIRGROUP_ID, MEM_ALIGN_READ_BYTE_AIR_IDS[0]),
        ];

        let binary_instances = vec![
            (ZISK_AIRGROUP_ID, BINARY_AIR_IDS[0]),
            (ZISK_AIRGROUP_ID, BINARY_ADD_AIR_IDS[0]),
            (ZISK_AIRGROUP_ID, BINARY_EXTENSION_AIR_IDS[0]),
        ];

        let accounts_bundle = AccountsSMBundle::new(self.poseidon_permuter.clone());

        let sm_bundle = StaticSMBundle::new(
            false,
            vec![
                (vec![(ZISK_AIRGROUP_ID, ROM_AIR_IDS[0])], StateMachines::RomSM(rom_sm.clone())),
                (mem_instances, StateMachines::MemSM(mem_sm.clone())),
                (binary_instances, StateMachines::BinarySM(binary_sm.clone())),
                (
                    vec![(ZISK_AIRGROUP_ID, ARITH_AIR_IDS[0])],
                    StateMachines::ArithSM(arith_sm.clone()),
                ),
                // The precompiles state machines
                (
                    vec![(ZISK_AIRGROUP_ID, KECCAKF_AIR_IDS[0])],
                    StateMachines::KeccakfManager(keccakf_sm.clone()),
                ),
                (
                    vec![(ZISK_AIRGROUP_ID, SHA_256_F_AIR_IDS[0])],
                    StateMachines::Sha256fManager(sha256f_sm.clone()),
                ),
                (
                    vec![(ZISK_AIRGROUP_ID, ARITH_EQ_AIR_IDS[0])],
                    StateMachines::ArithEqManager(arith_eq_sm.clone()),
                ),
                (
                    vec![(ZISK_AIRGROUP_ID, ARITH_EQ_384_AIR_IDS[0])],
                    StateMachines::ArithEq384Manager(arith_eq_384_sm.clone()),
                ),

            ],
            accounts_bundle.clone()
        );

        // Step 5: Create the executor and register the secondary state machines
        let executor: ZiskExecutor<F> = ZiskExecutor::new(
            zisk_rom,
            std,
            sm_bundle,
            self.chunk_size,
            self.world_rank,
            self.local_rank,
            self.base_port,
            self.unlock_mapped_memory,
            mem_init_slot,
            accounts_bundle.clone(),
            accounts
        );

        let executor = Arc::new(executor);

        // Step 7: Register the executor as a component in the Witness Manager
        wcm.register_component(executor.clone());

        self.executor = Some(executor);
    }

    /// Returns the execution result of the witness computation.
    ///
    /// # Returns
    /// * `u16` - The execution result code.
    fn get_execution_result(&self) -> Option<Box<dyn std::any::Any>> {
        match &self.executor {
            None => Some(Box::new(0u64) as Box<dyn Any>),
            Some(executor) => Some(Box::new(executor.get_execution_result()) as Box<dyn Any>),
        }
    }
}
