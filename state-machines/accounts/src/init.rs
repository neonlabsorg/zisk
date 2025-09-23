use std::{collections::BTreeMap, sync::{atomic::{AtomicBool, AtomicU32, AtomicU64}, Arc}};

use sbpf_parser::mem::TxInput;
use solana_sdk::{account::Account, instruction::{Instruction, InstructionError}};
use solana_pubkey::Pubkey;

use zisk_common::{AccountsInitBusData, BusDevice, BusDeviceMetrics, BusId, CheckPoint, ChunkId, InstanceType, MemBusData, Plan, Planner, ACCOUNTS_INIT_BUS_ID, MEM_BUS_ID};
use zisk_pil::{AccountsInitAccountsTrace, AccountsInitAccountsTraceRow, ACCOUNTS_INIT_AIR_IDS, ZISK_AIRGROUP_ID};

use proofman_common::{AirInstance, FromTrace, PreCalculate};

use fields::PrimeField64;

use zisk_common::{
    BusDeviceMetrics, ComponentBuilder, CounterStats, Instance, InstanceCtx,
    Planner,
};

pub struct AccountsInitSM {
    initial_state: Arc<TxInput>,
    stats: Arc<BTreeMap<u64, AtomicU32>>
}

impl AccountsInitSM {
    pub fn new(instruction: Instruction, accs: Vec<(Pubkey, Account)>) -> Result<Self, InstructionError> {
        let mut stats = BTreeMap::<u64, AtomicU32>::new();
        let input = TxInput::new_with_defaults(&instruction, accs.as_slice())?;
        for addr in input.iter() {
            stats.insert(addr, 0.into());
        }

        Ok(Self {
            initial_state: input.into(),
            stats: stats.into()
        })
    }
}

impl<F: PrimeField64> ComponentBuilder<F> for AccountsInitSM {
    fn build_instance(&self, ictx: InstanceCtx) -> Box<dyn Instance<F>> {
        Box::new(AccountsInitInstance { ictx, calculated: false.into(), stats: self.stats.clone(), initial_state: self.initial_state.clone() })
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
        let mut trace = AccountsInitAccountsTrace::<F>::new_from_vec(trace_buffer);

        let mut row = 0;
        for (i, addr) in self.initial_state.iter().enumerate() {
            trace[i].addr = F::from_u64(addr);
            let val = self.initial_state.read(addr).unwrap_or(0);
            trace[i].val_low = F::from_u32(val as u32);
            trace[i].val_high = F::from_u32((val >> 32) as u32);

            row += 1;
        }
        for i in row..trace.num_rows() {
            trace[i] = AccountsInitAccountsTraceRow::default();
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
        vec![ ACCOUNTS_INIT_BUS_ID ]
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
        debug_assert!(*bus_id == ACCOUNTS_INIT_BUS_ID);
        let addr = AccountsInitBusData::get_addr(data);
        if let Some(stats) = self.stats.get(&(addr as u64)) {
            stats.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        true
    }
}

pub struct AccountsInitPlanner;

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
