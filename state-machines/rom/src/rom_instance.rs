//! The `RomInstance` performs the witness computation based on the provided ROM execution plan
//!
//! It is responsible for computing witnesses for ROM-related execution plans,

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicU32},
        Arc,
    },
};

use crate::{rom_counter::RomCounter, RomSM};
use fields::PrimeField64;
use proofman_common::{AirInstance, ProofCtx, SetupCtx};
use std::sync::Mutex;
use zisk_common::{
    BusDevice, BusId, CheckPoint, ChunkId, CounterStats, Instance, InstanceCtx,
    InstanceType, MemCollectorInfo, Metrics, PayloadType, ROM_BUS_ID,
};
use zisk_core::ZiskRom;

/// The `RomInstance` struct represents an instance to perform the witness computations for
/// ROM-related execution plans.
///
/// It encapsulates the `ZiskRom` and its associated context, and it interacts with
/// the `RomSM` to compute witnesses for the given execution plan.
pub struct RomInstance {
    /// Reference to the Zisk ROM.
    zisk_rom: Arc<ZiskRom>,

    /// The instance context.
    ictx: InstanceCtx,

    inst_count: CounterStats,

    /// Execution statistics counter for ROM instructions.
    counter_stats: Mutex<Option<CounterStats>>,

    calculated: AtomicBool,
}

impl RomInstance {
    /// Creates a new `RomInstance`.
    ///
    /// # Arguments
    /// * `zisk_rom` - An `Arc`-wrapped reference to the Zisk ROM.
    /// * `ictx` - The `InstanceCtx` associated with this instance.
    ///
    /// # Returns
    /// A new `RomInstance` instance initialized with the provided ROM and context.
    pub fn new(
        zisk_rom: Arc<ZiskRom>,
        ictx: InstanceCtx,
        inst_count: CounterStats
    ) -> Self {
        Self {
            zisk_rom,
            ictx,
            inst_count,
            counter_stats: Mutex::new(None),
            calculated: AtomicBool::new(false),
        }
    }

    pub fn skip_collector(&self) -> bool {
        self.counter_stats.lock().unwrap().is_some()
    }

    pub fn build_rom_collector(&self, _chunk_id: ChunkId) -> Option<RomCollector> {
        if self.counter_stats.lock().unwrap().is_some() {
            return None;
        }

        Some(RomCollector::new(
            self.counter_stats.lock().unwrap().is_some(),
            RomCounter::new(CounterStats::copy_counters(&self.inst_count))
        ))
    }
}

impl<F: PrimeField64> Instance<F> for RomInstance {
    /// Computes the witness for the ROM execution plan.
    ///
    /// This method leverages the `RomSM` to generate an `AirInstance` based on the
    /// Zisk ROM and the provided execution plan.
    ///
    /// # Arguments
    /// * `_pctx` - The proof context, unused in this implementation.
    /// * `_sctx` - The setup context, unused in this implementation.
    /// * `_collectors` - A vector of input collectors to process and collect data for witness,
    ///   unused in this implementation.
    ///
    /// # Returns
    /// An `Option` containing the computed `AirInstance`.
    fn compute_witness(
        &self,
        _pctx: &ProofCtx<F>,
        _sctx: &SetupCtx<F>,
        collectors: Vec<(usize, Box<dyn BusDevice<PayloadType>>)>,
        trace_buffer: Vec<F>,
    ) -> Option<AirInstance<F>> {
        // Detach collectors and downcast to RomCollector
        if self.counter_stats.lock().unwrap().is_none() {
            let collectors: Vec<_> = collectors
                .into_iter()
                .map(|(_, collector)| collector.as_any().downcast::<RomCollector>().unwrap())
                .collect();

            let mut counter_stats = CounterStats::copy_counters(&self.inst_count);

            for collector in collectors {
                counter_stats += &collector.rom_counter.counter_stats;
            }

            *self.counter_stats.lock().unwrap() = Some(counter_stats);
        }

        let air_instance = Some(RomSM::compute_witness(
            &self.zisk_rom,
            self.counter_stats.lock().unwrap().as_ref().unwrap(),
            &self.calculated,
            trace_buffer,
        ));
        self.calculated.store(true, std::sync::atomic::Ordering::Relaxed);
        air_instance
    }

    fn reset(&self) {
        *self.counter_stats.lock().unwrap() = None;
        self.calculated.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Retrieves the checkpoint associated with this instance.
    ///
    /// # Returns
    /// A `CheckPoint` object representing the checkpoint of the execution plan.
    fn check_point(&self) -> &CheckPoint {
        &self.ictx.plan.check_point
    }

    /// Retrieves the type of this instance.
    ///
    /// # Returns
    /// An `InstanceType` representing the type of this instance (`InstanceType::Instance`).
    fn instance_type(&self) -> InstanceType {
        InstanceType::Instance
    }

    /// Builds an input collector for the instance.
    ///
    /// # Arguments
    /// * `chunk_id` - The chunk ID associated with the input collector.
    ///
    /// # Returns
    /// An `Option` containing the input collector for the instance.
    fn build_inputs_collector(&self, _: ChunkId) -> Option<Box<dyn BusDevice<PayloadType>>> {
        if self.counter_stats.lock().unwrap().is_some() {
            return None;
        }

        Some(Box::new(RomCollector::new(
            self.counter_stats.lock().unwrap().is_some(),
            RomCounter::new(CounterStats::copy_counters(&self.inst_count))
        )))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub struct RomCollector {
    /// Flag indicating if the table has been already computed.
    already_computed: bool,

    /// Execution statistics counter for the ROM.
    pub rom_counter: RomCounter,
}

impl RomCollector {
    /// Creates a new instance of `RomCounter`.
    ///
    /// # Returns
    /// A new `RomCounter` instance.
    pub fn new(
        computed: bool,
        rom_counter: RomCounter
    ) -> Self {
        Self { already_computed: computed, rom_counter }
    }
}

impl BusDevice<u64> for RomCollector {
    /// Processes data received on the bus, updating ROM metrics.
    ///
    /// # Arguments
    /// * `bus_id` - The ID of the bus sending the data.
    /// * `data` - The data received from the bus.
    /// * `pending` – A queue of pending bus operations used to send derived inputs.
    ///
    /// # Returns
    /// A boolean indicating whether the program should continue execution or terminate.
    /// Returns `true` to continue execution, `false` to stop.
    #[inline(always)]
    fn process_data(
        &mut self,
        bus_id: &BusId,
        data: &[u64],
        _pending: &mut VecDeque<(BusId, Vec<u64>)>,
        _mem_collector_info: Option<&[MemCollectorInfo]>,
    ) -> bool {
        debug_assert!(*bus_id == ROM_BUS_ID);

        if !self.already_computed {
            self.rom_counter.measure(data);
        }

        true
    }

    /// Returns the bus IDs associated with this counter.
    ///
    /// # Returns
    /// A vector containing the connected bus ID.
    fn bus_id(&self) -> Vec<BusId> {
        vec![ROM_BUS_ID]
    }

    /// Provides a dynamic reference for downcasting purposes.
    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}
