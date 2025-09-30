use std::{collections::BTreeMap, sync::{atomic::{AtomicBool, AtomicU32, AtomicU64}, Arc}};

use sbpf_parser::mem::TxInput;
use solana_sdk::{account::Account, instruction::{Instruction, InstructionError}};
use solana_pubkey::Pubkey;

use zisk_common::{AccountsBusData, BusDevice, BusDeviceMetrics, BusId, CheckPoint, ChunkId, InstanceType, MemBusData, Plan, Planner, ACCOUNTS_BUS_ID, ACCOUNTS_INIT_DATA_TYPE, MEM_BUS_ID};
use zisk_pil::{AccountsInitTrace, AccountsInitTraceRow, ACCOUNTS_INIT_AIR_IDS, ZISK_AIRGROUP_ID};

use proofman_common::{AirInstance, FromTrace, PreCalculate};

use fields::PrimeField64;

use zisk_common::{
    ComponentBuilder, CounterStats, Instance, InstanceCtx,
};

use crate::poseidon::{PoseidonSM, POSEIDON_WIDTH};

pub struct AccountsInitSM {
    initial_state: Arc<TxInput>,
    stats: Arc<BTreeMap<u64, AtomicU32>>
}

impl AccountsInitSM {
    pub fn new(input: Arc<TxInput>) -> Self {
        let mut stats = BTreeMap::<u64, AtomicU32>::new();
        for addr in input.iter() {
            stats.insert(addr, 0.into());
        }

        Self {
            initial_state: input.into(),
            stats: stats.into()
        }
    }
}

impl<F: PrimeField64> ComponentBuilder<F> for AccountsInitSM {
    fn build_instance(&self, ictx: InstanceCtx) -> Box<dyn Instance<F>> {
        Box::new(AccountsInitInstance { ictx, calculated: false.into(), stats: self.stats.clone(), initial_state: self.initial_state.clone(), poseidon: PoseidonSM::new() })
    }

    fn build_planner(&self) -> Box<dyn Planner> {
        Box::new(AccountsInitPlanner {})
    }

    fn build_counter(&self) -> Option<Box<dyn BusDeviceMetrics + 'static>> {
        None
    }
}

pub struct AccountsInitInstance {
    /// The instance context.
    ictx: InstanceCtx,

    initial_state: Arc<TxInput>,
    stats: Arc<BTreeMap<u64, AtomicU32>>,
    calculated: AtomicBool,

    poseidon: PoseidonSM
}

impl<F: PrimeField64> Instance<F> for AccountsInitInstance {
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
        let mut trace = AccountsInitTrace::<F>::new_from_vec(trace_buffer);

        let mut row = 0;
        let mut hash_input = [0; POSEIDON_WIDTH];
        for (i, addr) in self.initial_state.iter().enumerate() {
            trace[i].addr = F::from_u64(addr);
            let val = self.initial_state.read(addr).unwrap_or(0);
            let val = [val as u32, (val >> 32) as u32];
            trace[i].val[0] = F::from_u32(val[0]);
            trace[i].val[1] = F::from_u32(val[1]);
            trace[i].multiplicity = F::from_u32(self.stats.get(&addr).map(|x| x.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0));

            hash_input = self.poseidon.permute(&hash_input, &[addr, val[0].into(), val[1].into(), 0_u64]);
            trace[i].hash_accum = hash_input.map(|x| F::from_u64(x));

            row += 1;
        }
        for i in row..trace.num_rows() {
            trace[i] = AccountsInitTraceRow::default();
        }

        Some(AirInstance::new_from_trace(FromTrace::new(&mut trace)))
    }

    fn reset(&self) {
        self.calculated.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    fn build_inputs_collector(
            &self,
            _chunk_id: ChunkId,
        ) -> Option<Box<dyn zisk_common::BusDevice<zisk_common::PayloadType>>> 
    {
        Some(Box::new(AccountsInitCounter{stats: self.stats.clone() }))
    }
}

pub struct AccountsInitCounter {
    stats: Arc<BTreeMap<u64, AtomicU32>>,
}

impl BusDevice<u64> for AccountsInitCounter {
    fn bus_id(&self) -> Vec<zisk_common::BusId> {
        vec![ ACCOUNTS_BUS_ID, MEM_BUS_ID ]
    }

    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    fn process_data(
            &mut self,
            bus_id: &BusId,
            data: &[u64],
            _pending: &mut std::collections::VecDeque<(BusId, Vec<u64>)>,
        ) -> bool
    {
        debug_assert!(*bus_id == ACCOUNTS_BUS_ID);
        if AccountsBusData::val_type(data) == ACCOUNTS_INIT_DATA_TYPE {
            let addr = AccountsBusData::get_addr(data);
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
            PreCalculate::Slow,
            None,
        )]
    }
}
