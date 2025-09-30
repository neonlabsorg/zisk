use std::{collections::BTreeMap, sync::{atomic::AtomicBool, Arc, Mutex}};

use fields::PrimeField64;
use proofman_common::{AirInstance, FromTrace, PreCalculate};
use sbpf_parser::mem::TxInput;
use zisk_common::{AccountsBusData, BusDevice, BusDeviceMetrics, CheckPoint, ChunkId, ComponentBuilder, Instance, InstanceCtx, InstanceType, Plan, Planner, ACCOUNTS_BUS_ID, ACCOUNTS_RESULT_DATA_TYPE};
use zisk_pil::{AccountsResultTrace, AccountsResultTraceRow, ACCOUNTS_RESULT_AIR_IDS, ZISK_AIRGROUP_ID};

use crate::poseidon::{PoseidonSM, POSEIDON_WIDTH};

#[derive(Clone)]
struct AccountsResultStats(Arc<BTreeMap<u64, Mutex<Option<[u64; 2]>>>>);

pub struct AccountsResultSM {
    initial_state: Arc<TxInput>,
    final_state: Arc<TxInput>,
    writes: AccountsResultStats
}

impl AccountsResultSM {
    pub fn new(initial_state: Arc<TxInput>, final_state: Arc<TxInput>) -> Self {
        let mut writes = BTreeMap::new();

        for addr in final_state.iter() {
            writes.insert(addr, None.into());
        }

        Self {
            initial_state,
            final_state,
            writes: AccountsResultStats(writes.into())
        }
    }
}

pub struct AccountsResultPlanner;

impl Planner for AccountsResultPlanner {
    fn plan(&self, metrics: Vec<(ChunkId, Box<dyn BusDeviceMetrics>)>) -> Vec<Plan> {
        if metrics.is_empty() {
            panic!("RomPlanner::plan() No metrics found");
        }

        let vec_chunk_ids = metrics.iter().map(|(chunk_id, _)| *chunk_id).collect::<Vec<_>>();

        vec![Plan::new(
            ZISK_AIRGROUP_ID,
            ACCOUNTS_RESULT_AIR_IDS[0],
            None,
            InstanceType::Instance,
            CheckPoint::Multiple(vec_chunk_ids),
            PreCalculate::Slow,
            None,
        )]
    }
}



impl<F: PrimeField64> ComponentBuilder<F> for AccountsResultSM {
    fn build_planner(&self) -> Box<dyn zisk_common::Planner> {
        Box::new(AccountsResultPlanner)
    }

    fn build_counter(&self) -> Option<Box<dyn BusDeviceMetrics>> {
        None
    }

    fn build_instance(&self, ictx: InstanceCtx) -> Box<dyn Instance<F>> {
        Box::new(AccountsResultInstance { 
            ictx,
            calculated: false.into(),
            stats: self.writes.clone(),
            initial_state: self.final_state.clone(),
            final_state: self.final_state.clone(),
            poseidon: PoseidonSM::new()
        })
    }
}

struct AccountsResultInstance {
    ictx: InstanceCtx,

    initial_state: Arc<TxInput>,
    final_state: Arc<TxInput>,
    calculated: AtomicBool,
    stats: AccountsResultStats,

    poseidon: PoseidonSM
}


impl<F: PrimeField64> Instance<F> for AccountsResultInstance {
    fn check_point(&self) -> &CheckPoint {
        &self.ictx.plan.check_point
    }

    fn instance_type(&self) -> InstanceType {
        InstanceType::Instance
    }

    fn compute_witness(
            &self,
            _pctx: &proofman_common::ProofCtx<F>,
            _sctx: &proofman_common::SetupCtx<F>,
            _collectors: Vec<(usize, Box<dyn zisk_common::BusDevice<zisk_common::PayloadType>>)>,
            trace_buffer: Vec<F>,
        ) -> Option<proofman_common::AirInstance<F>> 
    {
        let mut trace = AccountsResultTrace::<F>::new_from_vec(trace_buffer);

        let mut row = 0;
        let mut hash_input = [0; POSEIDON_WIDTH];
        for (i, addr) in self.final_state.iter().enumerate() {
            trace[i].addr = F::from_u64(addr);
            let val = self.final_state.read(addr).unwrap_or(0);
            let val = [val as u32, (val >> 32) as u32];
            trace[i].val = val.map(F::from_u32);

            let val_init = self.initial_state.read(addr).unwrap_or(0);
            let val_init = [val_init as u32, (val_init >> 32) as u32];
            trace[i].val_init = val_init.map(F::from_u32);

            let vals = self.stats.0.get(&addr).unwrap().lock().unwrap().clone();
            trace[i].sel_wr = F::from_bool(vals.is_some());
            trace[i].val_wr = vals.map_or([F::ZERO; 2], |x| x.map(F::from_u64));

            hash_input = self.poseidon.permute(&hash_input, &[addr, val[0].into(), val[1].into(), 0_u64]);
            trace[i].hash_accum = hash_input.map(|x| F::from_u64(x));

            row += 1;
        }
        for i in row..trace.num_rows() {
            trace[i] = AccountsResultTraceRow::default();
        }

        Some(AirInstance::new_from_trace(FromTrace::new(&mut trace)))
    }

    fn build_inputs_collector(
            &self,
            _chunk_id: ChunkId,
        ) -> Option<Box<dyn BusDevice<zisk_common::PayloadType>>> {
        Some(Box::new(AccountsResultCounter{ stats: self.stats.clone() }))
    }
}

struct AccountsResultCounter {
    stats: AccountsResultStats
}

impl BusDevice<u64> for AccountsResultCounter {
    fn bus_id(&self) -> Vec<zisk_common::BusId> {
        vec![ACCOUNTS_BUS_ID]
    }

    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    fn process_data(
            &mut self,
            bus_id: &zisk_common::BusId,
            data: &[u64],
            _pending: &mut std::collections::VecDeque<(zisk_common::BusId, Vec<u64>)>,
        ) -> bool {
        debug_assert!(*bus_id == ACCOUNTS_BUS_ID);

        if AccountsBusData::val_type(data) == ACCOUNTS_RESULT_DATA_TYPE {
            if let Some(vals) = self.stats.0.get(&AccountsBusData::get_addr(data).into()) {
                *vals.lock().unwrap() = Some(AccountsBusData::values(data));
            }
        }

        true
    }
}
