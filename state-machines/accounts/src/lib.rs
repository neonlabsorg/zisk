use std::{collections::BTreeMap, sync::{atomic::{AtomicBool, AtomicU32, AtomicU64}, Arc}};

use sbpf_parser::mem::TxInput;
use solana_sdk::{account::Account, instruction::{Instruction, InstructionError}};
use zisk_core::ZiskRom;
use solana_pubkey::Pubkey;

use zisk_common::{BusDevice, BusDeviceMetrics, BusId, CheckPoint, ChunkId, InstanceType, Plan, Planner};
use zisk_pil::{ACCOUNTS_AIR_IDS, ZISK_AIRGROUP_ID};

use proofman_common::PreCalculate;

use fields::PrimeField64;

use zisk_common::{
    create_atomic_vec, BusDeviceMetrics, ComponentBuilder, CounterStats, Instance, InstanceCtx,
    Planner,
};

pub struct AccountsSM {
    initial_state: TxInput,
    stats: Arc<BTreeMap<u64, AtomicU32>>
}

impl AccountsSM {
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

impl<F: PrimeField64> ComponentBuilder<F> for AccountsSM {
    fn build_instance(&self, ictx: InstanceCtx) -> Box<dyn Instance<F>> {
        Box::new(AccountsInstance { ictx, calculated: false.into(), stats: self.stats.clone() })
    }

    fn build_planner(&self) -> Box<dyn Planner> {
        Box::new(AccountsPlanner {})
    }

    fn build_counter(&self) -> Option<Box<dyn BusDeviceMetrics + 'static>> {
        None
    }
}

pub struct AccountsInstance {
    /// The instance context.
    ictx: InstanceCtx,

    stats: Arc<BTreeMap<u64, AtomicU32>>,
    calculated: AtomicBool,
}

impl<F: PrimeField64> Instance<F> for AccountsInstance {
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
            _trace_buffer: Vec<F>,
        ) -> Option<proofman_common::AirInstance<F>> 
    {
    }

    fn reset(&self) {
        self.calculated.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    fn build_inputs_collector(
            &self,
            _chunk_id: ChunkId,
        ) -> Option<Box<dyn zisk_common::BusDevice<zisk_common::PayloadType>>> 
    {
        Some(Box::new(AccountsCounter{stats: self.stats.clone(), bus_id: BusId{ 0: ACCOUNTS_AIR_IDS[0] } }))
    }
}

pub struct AccountsCollector {
}

pub struct AccountsCounter {
    stats: Arc<BTreeMap<u64, AtomicU32>>,
    bus_id: BusId
}

impl BusDevice<u64> for AccountsCounter {
    fn bus_id(&self) -> Vec<zisk_common::BusId> {
        vec![self.bus_id]
    }

    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    fn process_data(
            &mut self,
            bus_id: &BusId,
            data: &[u64],
            pending: &mut std::collections::VecDeque<(BusId, Vec<u64>)>,
        ) -> bool
    {
    }
}

pub struct AccountsPlanner;

impl Planner for AccountsPlanner {
    fn plan(&self, metrics: Vec<(ChunkId, Box<dyn BusDeviceMetrics>)>) -> Vec<Plan> {
        if metrics.is_empty() {
            panic!("RomPlanner::plan() No metrics found");
        }

        let vec_chunk_ids = metrics.iter().map(|(chunk_id, _)| *chunk_id).collect::<Vec<_>>();

        vec![Plan::new(
            ZISK_AIRGROUP_ID,
            ACCOUNTS_AIR_IDS[0],
            None,
            InstanceType::Instance,
            CheckPoint::Multiple(vec_chunk_ids),
            PreCalculate::Slow,
            None,
        )]
    }
}
