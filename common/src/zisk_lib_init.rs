use std::path::PathBuf;

use proofman_common::VerboseMode;
use witness::WitnessLibrary;

pub type ZiskLibInitFn<F> =
    fn(
        VerboseMode,
        PathBuf,         // Rom path
<<<<<<< HEAD
        Option<PathBuf>, // Asm path
        Option<PathBuf>, // Asm ROM path
||||||| parent of dee8e3cd (replace the emulator)
        Option<PathBuf>, // Asm path
        Option<PathBuf>, // Asm ROM path
        Option<u64>,     // Chunk size
=======
        Option<u64>,     // Chunk size
>>>>>>> dee8e3cd (replace the emulator)
        Option<i32>,     // mpi World Rank
        Option<i32>,     // mpi Local Rank
        Option<u16>,     // Base port for the ASM microservices
        bool,            // Unlock_mapped_memory
        bool,            // Shared_tables
    ) -> Result<Box<dyn WitnessLibrary<F> + Send + Sync>, Box<dyn std::error::Error>>;
