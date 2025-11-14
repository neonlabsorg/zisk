use std::{collections::BTreeMap, sync::{atomic::{AtomicBool, AtomicU32}, Arc}};

use sbpf_parser::mem::TxInput;
use mem_common::{MemHelpers, MEM_BYTES};

use zisk_common::{ BusDevice, BusDeviceMetrics, BusId, CheckPoint, ChunkId, InstanceType, MemBusData, MemCollectorInfo, Plan, Planner, MEM_BUS_ID};
use zisk_pil::{AccountsInitTrace, AccountsInitTraceRow, ACCOUNTS_INIT_AIR_IDS, ZISK_AIRGROUP_ID};

use proofman_common::{AirInstance, FromTrace};

use fields::PrimeField64;

use zisk_common::{
    ComponentBuilder, Instance, InstanceCtx,
};

use crate::poseidon::{PoseidonSM, POSEIDON_BITRATE, POSEIDON_WIDTH};

#[derive(Clone)]
pub struct AccountsInitSM<F: PrimeField64> {
    initial_state: Arc<TxInput>,
    stats: Arc<BTreeMap<u64, AtomicU32>>,
    poseidon: PoseidonSM<F>
}

impl<F: PrimeField64> AccountsInitSM<F> {
    pub fn new(input: Arc<TxInput>, poseidon: PoseidonSM<F>) -> Self {
        let mut stats = BTreeMap::<u64, AtomicU32>::new();
        for addr in input.iter() {
            stats.insert(addr, 0.into());
        }

        Self {
            initial_state: input.into(),
            stats: stats.into(),
            poseidon
        }
    }

    pub fn record_hashes(&self) -> [F; POSEIDON_BITRATE] {
        let mut hash_input = [F::ZERO; POSEIDON_WIDTH];
        for (_i, addr) in self.initial_state.iter().enumerate() {
            let val = self.initial_state.read(addr).unwrap_or(0);
            let val = [F::from_u32(val as u32), F::from_u32((val >> 32) as u32)];

            let input = [F::from_u64(addr / MEM_BYTES), val[0], val[1], F::ZERO];
            self.poseidon.record(&hash_input, &input);
            hash_input = self.poseidon.permute(&hash_input, &input);
        }
        self.poseidon.output(&hash_input)
    }

    fn compute_witness(
            &self,
            trace_buffer: Vec<F>,
        ) -> Option<proofman_common::AirInstance<F>> 
    {
        let mut trace = AccountsInitTrace::<F>::new_from_vec(trace_buffer);

        let mut row = 0;
        let mut hash_input = [F::ZERO; POSEIDON_WIDTH];
        for (i, addr) in self.initial_state.iter().enumerate() {
            trace[i].addr = F::from_u64(addr / MEM_BYTES);
            let val = self.initial_state.read(addr).unwrap_or(0);
            let val = [F::from_u32(val as u32), F::from_u32((val >> 32) as u32)];
            trace[i].val = val.clone();
            trace[i].multiplicity = F::from_u32(self.stats.get(&addr).map(|x| x.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0));

            hash_input = self.poseidon.permute(&hash_input, &[F::from_u64(addr / MEM_BYTES), val[0], val[1], F::ZERO]);
            trace[i].hash_accum = hash_input;
            trace[i].sel = F::ONE;

            row += 1;
        }

        tracing::info!(
            "··· Creating Init mem [{} / {} rows filled {:.2}%]",
            row,
            trace.num_rows(),
            row as f64 / trace.num_rows() as f64 * 100.0
        );

        for i in row..trace.num_rows() {
            trace[i] = trace[row - 1].clone();
            trace[i].sel = F::ZERO;
        }

        Some(AirInstance::new_from_trace(FromTrace::new(&mut trace)))
    }

    pub fn build_counter(&self) -> AccountsInitCounter {
        AccountsInitCounter {
            stats: self.stats.clone()
        }
    }
}

impl<F: PrimeField64> ComponentBuilder<F> for AccountsInitSM<F> {
    fn build_instance(&self, ictx: InstanceCtx) -> Box<dyn Instance<F>> {
        Box::new(AccountsInitInstance { ictx, calculated: false.into(), sm: self.clone() })
    }

    fn build_planner(&self) -> Box<dyn Planner + 'static> {
        Box::new(AccountsInitPlanner {})
    }

    fn build_counter(&self) -> Option<Box<dyn BusDeviceMetrics + 'static>> {
        None
    }
}

pub struct AccountsInitInstance<F: PrimeField64> {
    /// The instance context.
    ictx: InstanceCtx,

    calculated: AtomicBool,
    sm: AccountsInitSM<F>
}

impl<F: PrimeField64> Instance<F> for AccountsInitInstance<F> {
    fn instance_type(&self) -> InstanceType {
        InstanceType::Instance
    }

    fn check_point(&self) -> &CheckPoint {
        &self.ictx.plan.check_point
    }

    fn compute_witness(
            &self,
            _pctx: &proofman_common::ProofCtx<F>,
            _sctx: &proofman_common::SetupCtx<F>,
            _collectors: Vec<(usize, Box<dyn zisk_common::BusDevice<zisk_common::PayloadType>>)>,
            trace_buffer: Vec<F>,
        ) -> Option<proofman_common::AirInstance<F>> 
    {
        self.sm.compute_witness(trace_buffer)
    }

    fn reset(&self) {
        self.calculated.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    fn build_inputs_collector(
            &self,
            _chunk_id: ChunkId,
        ) -> Option<Box<dyn zisk_common::BusDevice<zisk_common::PayloadType>>> 
    {
        Some(Box::new(AccountsInitCounter{stats: self.sm.stats.clone() }))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub struct AccountsInitCounter {
    stats: Arc<BTreeMap<u64, AtomicU32>>,
}

impl BusDevice<u64> for AccountsInitCounter {
    fn bus_id(&self) -> Vec<zisk_common::BusId> {
        vec![ MEM_BUS_ID ]
    }

    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    fn process_data(
            &mut self,
            bus_id: &BusId,
            data: &[u64],
            _pending: &mut std::collections::VecDeque<(BusId, Vec<u64>)>,
            _mem_collector_info: Option<&[MemCollectorInfo]>,
        ) -> bool
    {
        debug_assert!(*bus_id == MEM_BUS_ID );
        if !MemHelpers::is_write(MemBusData::get_op(data)) {
            let addr = MemBusData::get_addr(data);
            if let Some(stats) = self.stats.get(&(addr as u64)) {
                stats.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        true
    }
}

struct AccountsInitPlanner;

impl Planner for AccountsInitPlanner {
    fn plan(&self, metrics: Vec<(ChunkId, Box<dyn BusDeviceMetrics>)>) -> Vec<Plan> {
        if metrics.is_empty() {
            panic!("RomPlanner::plan() No metrics found");
        }

        let vec_chunk_ids = metrics.iter().map(|(chunk_id, _)| *chunk_id).collect::<Vec<_>>();

        vec![Plan::new(
            ZISK_AIRGROUP_ID,
            ACCOUNTS_INIT_AIR_IDS[0],
            None,
            InstanceType::Instance,
            CheckPoint::Multiple(vec_chunk_ids),
            None,
            1,
        )]
    }
}
