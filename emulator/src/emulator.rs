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

use crate::{Emu, EmuOptions, ParEmuOptions, ZiskEmulatorErr};

use data_bus::DataBusTrait;
use fields::PrimeField;
use sbpf_parser::mem::TxInput;
use std::sync::Arc;
use zisk_common::EmuTrace;
use zisk_core::ZiskRom;

pub trait Emulator {
    fn emulate(
        &self,
        options: &EmuOptions,
        callback: Option<impl Fn(EmuTrace)>,
    ) -> Result<Vec<u8>, ZiskEmulatorErr>;
}
pub struct ZiskEmulator;

impl ZiskEmulator {
<<<<<<< HEAD
    /// Lists all device-under-test riscof files in a directory (*dut*.elf) and calls
    /// process_elf_file with each of them
    fn process_directory(
        directory: String,
        inputs: &[u8],
        options: &EmuOptions,
    ) -> Result<Vec<u8>, ZiskEmulatorErr> {
        if options.verbose {
            println!("process_directory() directory={directory}");
        }

        // List all files in the directory
        let files = Self::list_files(&directory).unwrap();

        // For every file
        for file in files {
            // If file follows the riscof dut file name convention, then call process_elf_file()
            if file.contains("dut") && file.ends_with(".elf") {
                Self::process_elf_file(file, inputs, options, None::<Box<dyn Fn(EmuTrace)>>)?;
            }
        }

        Ok(Vec::new())
    }

    /// Processes an RISC-V ELF file
    fn process_elf_file(
        elf_filename: String,
        inputs: &[u8],
        options: &EmuOptions,
        callback: Option<impl Fn(EmuTrace)>,
    ) -> Result<Vec<u8>, ZiskEmulatorErr> {
        if options.verbose {
            println!("process_elf_file() elf_file={elf_filename}");
        }

        // Create an instance of the RISC-V -> ZisK program transpiler (Riscv2zisk) with the ELF
        // file name
        let riscv2zisk = Riscv2zisk::new(elf_filename);

        // Convert the ELF file to ZisK ROM calling the transpiler run() method
        let zisk_rom = riscv2zisk.run().map_err(|err| ZiskEmulatorErr::Unknown(err.to_string()))?;

        // Process the Zisk rom with the provided inputs, according to the configured options
        Self::process_rom(&zisk_rom, inputs, options, callback)
    }

    // To be implemented
    fn process_rom_file(
        rom_filename: String,
        inputs: &[u8],
        options: &EmuOptions,
        callback: Option<impl Fn(EmuTrace)>,
    ) -> Result<Vec<u8>, ZiskEmulatorErr> {
        if options.verbose {
            println!("process_rom_file() rom_file={rom_filename}");
        }

        // TODO: load from file
        let rom: ZiskRom = ZiskRom::default();
        Self::process_rom(&rom, inputs, options, callback)
    }

    /// Processes a Zisk rom with the provided inputs, according to the configured options
    pub fn process_rom(
        rom: &ZiskRom,
        inputs: &[u8],
        options: &EmuOptions,
        callback: Option<impl Fn(EmuTrace)>,
    ) -> Result<Vec<u8>, ZiskEmulatorErr> {
        if options.verbose {
            println!("process_rom() rom size={} inputs size={}", rom.insts.len(), inputs.len());
        }

        // Create a emulator instance with the Zisk rom
        let mut emu = Emu::new(rom);

        // Get the current time, to be used to calculate the metrics
        let start = Instant::now();

        // Run the emulation, using the input and the options
        emu.run(inputs.to_owned(), options, callback);

        // Check that the emulation completed, either successfully or not, but it must reach the end
        // of the program
        if !emu.terminated() {
            return Err(ZiskEmulatorErr::EmulationNoCompleted);
        }

        // Store the duration of the emulation process as a difference vs. the start time
        let duration = start.elapsed();

        // Log performance metrics
        if options.log_metrics {
            let secs = duration.as_secs_f64();
            let steps = emu.number_of_steps();
            let tp = steps as f64 / secs / 1_000_000.0;

            let system = System::new_all();
            let cpu = &system.cpus()[0];
            let cpu_frequency = cpu.frequency() as f64;

            let clocks_per_step = cpu_frequency / tp;
            println!(
                "process_rom() steps={steps} duration={secs:.4} tp={tp:.4} Msteps/s freq={cpu_frequency:.4} {clocks_per_step:.4} clocks/step"
            );
        }

        // Get the emulation output
        let output = emu.get_output_8();

        // OUTPUT:
        // Save output to a file if requested
        if options.output.is_some() {
            fs::write(options.output.as_ref().unwrap(), &output)
                .map_err(|e| ZiskEmulatorErr::Unknown(e.to_string()))?
        }

        // Log output to console if requested
        if options.log_output {
            // Get the emulation output as a u32 vector
            let output = emu.get_output_32();

            // Log the output to console
            for o in &output {
                println!("{o:08x}");
            }
        }

        Ok(output)
    }

||||||| parent of dee8e3cd (replace the emulator)
    /// Lists all device-under-test riscof files in a directory (*dut*.elf) and calls
    /// process_elf_file with each of them
    fn process_directory(
        directory: String,
        inputs: &[u8],
        options: &EmuOptions,
    ) -> Result<Vec<u8>, ZiskEmulatorErr> {
        if options.verbose {
            println!("process_directory() directory={directory}");
        }

        // List all files in the directory
        let files = Self::list_files(&directory).unwrap();

        // For every file
        for file in files {
            // If file follows the riscof dut file name convention, then call process_elf_file()
            if file.contains("dut") && file.ends_with(".elf") {
                Self::process_elf_file(file, inputs, options, None::<Box<dyn Fn(EmuTrace)>>)?;
            }
        }

        Ok(Vec::new())
    }

    /// Processes an RISC-V ELF file
    fn process_elf_file(
        elf_filename: String,
        inputs: &[u8],
        options: &EmuOptions,
        callback: Option<impl Fn(EmuTrace)>,
    ) -> Result<Vec<u8>, ZiskEmulatorErr> {
        if options.verbose {
            println!("process_elf_file() elf_file={elf_filename}");
        }

        // Create an instance of the RISC-V -> ZisK program transpiler (Riscv2zisk) with the ELF
        // file name
        let riscv2zisk = Riscv2zisk::new(elf_filename);

        // Convert the ELF file to ZisK ROM calling the transpiler run() method
        let zisk_rom = riscv2zisk.run().map_err(|err| ZiskEmulatorErr::Unknown(err.to_string()))?;

        // Process the Zisk rom with the provided inputs, according to the configured options
        Self::process_rom(&zisk_rom, inputs, options, callback)
    }

    // To be implemented
    fn process_rom_file(
        rom_filename: String,
        inputs: &[u8],
        options: &EmuOptions,
        callback: Option<impl Fn(EmuTrace)>,
    ) -> Result<Vec<u8>, ZiskEmulatorErr> {
        if options.verbose {
            println!("process_rom_file() rom_file={rom_filename}");
        }

        // TODO: load from file
        let rom: ZiskRom = ZiskRom::default();
        Self::process_rom(&rom, inputs, options, callback)
    }

    /// Processes a Zisk rom with the provided inputs, according to the configured options
    pub fn process_rom(
        rom: &ZiskRom,
        inputs: &[u8],
        options: &EmuOptions,
        callback: Option<impl Fn(EmuTrace)>,
    ) -> Result<Vec<u8>, ZiskEmulatorErr> {
        if options.verbose {
            println!("process_rom() rom size={} inputs size={}", rom.insts.len(), inputs.len());
        }

        // Create a emulator instance with the Zisk rom
        let mut emu = Emu::new(rom, options.chunk_size.unwrap_or(1u64 << 18));

        // Get the current time, to be used to calculate the metrics
        let start = Instant::now();

        // Run the emulation, using the input and the options
        emu.run(inputs.to_owned(), options, callback);

        // Check that the emulation completed, either successfully or not, but it must reach the end
        // of the program
        if !emu.terminated() {
            return Err(ZiskEmulatorErr::EmulationNoCompleted);
        }

        // Store the duration of the emulation process as a difference vs. the start time
        let duration = start.elapsed();

        // Log performance metrics
        if options.log_metrics {
            let secs = duration.as_secs_f64();
            let steps = emu.number_of_steps();
            let tp = steps as f64 / secs / 1_000_000.0;

            let system = System::new_all();
            let cpu = &system.cpus()[0];
            let cpu_frequency = cpu.frequency() as f64;

            let clocks_per_step = cpu_frequency / tp;
            println!(
                "process_rom() steps={steps} duration={secs:.4} tp={tp:.4} Msteps/s freq={cpu_frequency:.4} {clocks_per_step:.4} clocks/step"
            );
        }

        // Get the emulation output
        let output = emu.get_output_8();

        // OUTPUT:
        // Save output to a file if requested
        if options.output.is_some() {
            fs::write(options.output.as_ref().unwrap(), &output)
                .map_err(|e| ZiskEmulatorErr::Unknown(e.to_string()))?
        }

        // Log output to console if requested
        if options.log_output {
            // Get the emulation output as a u32 vector
            let output = emu.get_output_32();

            // Log the output to console
            for o in &output {
                println!("{o:08x}");
            }
        }

        Ok(output)
    }

=======
>>>>>>> dee8e3cd (replace the emulator)
    /// EXECUTE phase
    /// First phase of the witness computation
    /// 8 threads in waterfall (# threads to be re-calibrated after memory reads refactor)
    /// Must be fast
    pub fn compute_minimal_traces(
        rom: &ZiskRom,
        inputs: &[u8],
        options: &EmuOptions,
        accounts: &[(solana_pubkey::Pubkey, solana_account::Account)]
    ) -> Result<(Vec<EmuTrace>, (Arc<TxInput>, Arc<TxInput>)), ZiskEmulatorErr> {
        let par_emu_options =
            ParEmuOptions::new(1, 0, options.chunk_size.unwrap() as usize);

        // Run the emulation
        let mut emu = Emu::new(rom, options.chunk_size.unwrap());

<<<<<<< HEAD
            // Run the emulation
            let mut emu = Emu::new(rom);
            let result = emu.par_run(inputs.to_owned(), options, &par_emu_options);

            if !emu.terminated() {
                panic!("Emulation did not complete");
                // TODO!
                // return Err(ZiskEmulatorErr::EmulationNoCompleted);
            }

            *emu_trace = result;
        });

        let capacity = minimal_traces.iter().map(|trace| trace.len()).sum::<usize>();
        let mut vec_traces = Vec::with_capacity(capacity);
        for i in 0..capacity {
            let x = i % num_threads;
            let y = i / num_threads;

            vec_traces.push(std::mem::take(&mut minimal_traces[x][y]));
        }

        Ok(vec_traces)
||||||| parent of dee8e3cd (replace the emulator)
            // Run the emulation
            let mut emu = Emu::new(rom, options.chunk_size.unwrap());
            let result = emu.par_run(inputs.to_owned(), options, &par_emu_options);

            if !emu.terminated() {
                panic!("Emulation did not complete");
                // TODO!
                // return Err(ZiskEmulatorErr::EmulationNoCompleted);
            }

            *emu_trace = result;
        });

        let capacity = minimal_traces.iter().map(|trace| trace.len()).sum::<usize>();
        let mut vec_traces = Vec::with_capacity(capacity);
        for i in 0..capacity {
            let x = i % num_threads;
            let y = i / num_threads;

            vec_traces.push(std::mem::take(&mut minimal_traces[x][y]));
        }

        Ok(vec_traces)
=======
        // I don't run any threads so it should be safe
        emu.run_gen_trace(inputs.to_owned(), options, &par_emu_options, accounts).map_err(ZiskEmulatorErr::SolanaEmulationError)
>>>>>>> dee8e3cd (replace the emulator)
    }

    /// COUNT phase
    /// Second phase of the witness computation
    /// Executes in parallel the different blocks of wc
    /// Good to be fast
    pub fn process_emu_trace<F: PrimeField, T, DB: DataBusTrait<u64, T>>(
        rom: &ZiskRom,
        emu_trace: &EmuTrace,
        data_bus: &mut DB,
        with_mem_ops: bool,
    ) {
        // Create a emulator instance with this rom
        let mut emu = Emu::new(rom);

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
    ) {
        // Create a emulator instance with this rom
        let mut emu = Emu::new(rom);

        // Run the emulation
        emu.process_emu_traces(min_traces, chunk_id, data_bus);
    }
}
