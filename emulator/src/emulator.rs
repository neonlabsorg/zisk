//! ZiskEmulator
//!
//! ```text
//! ziskemu.main()
//!  \
//!   emulate()
//!    \
//!     process_directory() -> lists *dut*.elf files
//!      \
//!       process_elf_file()
//!        \
//!         - Riscv2zisk::run()
//!         - process_rom()
//!            \
//!             Emu::run()
//! ```

use crate::{Emu, EmuOptions, ErrWrongArguments, ParEmuOptions, ZiskEmulatorErr};

use data_bus::DataBusTrait;
use fields::{Goldilocks, PrimeField, PrimeField64};
use sm_accounts::AccountsSMBundle;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};
use sysinfo::System;
use zisk_common::EmuTrace;
use zisk_core::ZiskRom;

use svm_tracer::InstructionTraceBuilder;
use mollusk_svm::Mollusk;

pub trait Emulator {
    fn emulate(
        &self,
        options: &EmuOptions,
        callback: Option<impl Fn(EmuTrace)>,
    ) -> Result<Vec<u8>, ZiskEmulatorErr>;
}
pub struct ZiskEmulator;

impl ZiskEmulator {
    /// EXECUTE phase
    /// First phase of the witness computation
    /// 8 threads in waterfall (# threads to be re-calibrated after memory reads refactor)
    /// Must be fast
    pub fn compute_minimal_traces<F: PrimeField64>(
        rom: &ZiskRom,
        inputs: &[u8],
        options: &EmuOptions,
        accounts_sm: &AccountsSMBundle<F>,
        accounts: &[(solana_pubkey::Pubkey, solana_account::Account)]
    ) -> Result<Vec<EmuTrace>, ZiskEmulatorErr> {
        let par_emu_options =
            ParEmuOptions::new(1, 0, options.chunk_size.unwrap() as usize);

        // Run the emulation
        let mut emu = Emu::new(rom, options.chunk_size.unwrap());

        // I don't run any threads so it should be safe
        emu.run_gen_trace(inputs.to_owned(), options, &par_emu_options, accounts_sm, accounts).map_err(ZiskEmulatorErr::SolanaEmulationError)
    }

    /// COUNT phase
    /// Second phase of the witness computation
    /// Executes in parallel the different blocks of wc
    /// Good to be fast
    pub fn process_emu_trace<F: PrimeField, T, DB: DataBusTrait<u64, T>>(
        rom: &ZiskRom,
        emu_trace: &EmuTrace,
        data_bus: &mut DB,
        chunk_size: u64,
        with_mem_ops: bool,
    ) {
        // Create a emulator instance with this rom
        let mut emu = Emu::new(rom, chunk_size);

        // Run the emulation
        emu.process_emu_trace(emu_trace, data_bus, with_mem_ops);
    }

    /// EXPAND phase
    /// Third phase of the witness computation
    /// I have a
    pub fn process_emu_traces<F: PrimeField, T, DB: DataBusTrait<u64, T>>(
        rom: &ZiskRom,
        min_traces: &[EmuTrace],
        chunk_id: usize,
        data_bus: &mut DB,
        chunk_size: u64,
    ) {
        // Create a emulator instance with this rom
        let mut emu = Emu::new(rom, chunk_size);

        // Run the emulation
        emu.process_emu_traces(min_traces, chunk_id, data_bus);
    }
}
