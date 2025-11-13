use fields::{Goldilocks, PrimeField64};
use zisk_common::{ComponentBuilder, Instance, InstanceCtx};
use init::{AccountsInitCounter, AccountsInitSM};
use poseidon::{PoseidonPermuter, PoseidonSM};
use result::{AccountsResultCounter, AccountsResultSM};
use sbpf_parser::mem::TxInput;
use zisk_common::{BusDeviceMetrics, ChunkId, Plan};
use zisk_pil::{ACCOUNTS_INIT_AIR_IDS, ACCOUNTS_RESULT_AIR_IDS, POSEIDON_PERMUTER_AIR_IDS, ZISK_AIRGROUP_ID};
use std::{collections::HashMap, sync::{Arc, RwLock}};

use crate::poseidon::POSEIDON_BITRATE;

pub mod init;
pub mod result;
pub mod poseidon;


#[derive(Clone)]
pub struct AccountsSMBundle<F: PrimeField64> {
    init_sm: Arc<RwLock<Option<AccountsInitSM<F>>>>,
    result_sm: Arc<RwLock<Option<AccountsResultSM<F>>>>,
    poseidon_sm: Arc<RwLock<Option<PoseidonSM<F>>>>,
    poseidon_permuter: PoseidonPermuter<F>
}

pub const ACCOUNTS_INIT_ID: usize = 11;
pub const ACCOUNTS_RESULT_ID: usize = 12;
pub const PERMUTER_ID: usize = 13;

pub enum BuiltInstance<F: PrimeField64> {
    Built(Box<dyn Instance<F>>),
    NotRecognized(InstanceCtx),
}

impl<F: PrimeField64> AccountsSMBundle<F> {
    pub fn new(poseidon_permuter: PoseidonPermuter<F>) -> Self {
        Self {
            init_sm: Arc::new(None.into()),
            result_sm: Arc::new(None.into()),
            poseidon_sm: Arc::new(None.into()),
            poseidon_permuter
        }
    }

    pub fn initialize(&self, init_state: Arc<TxInput>, final_state: Arc<TxInput>) -> ([F; POSEIDON_BITRATE], [F; POSEIDON_BITRATE]) {
        let poseidon = PoseidonSM::new(self.poseidon_permuter.clone());
        *self.poseidon_sm.write().unwrap() = Some(poseidon.clone());

        let accounts_init = AccountsInitSM::new(init_state.clone(), poseidon.clone());
        let init_hash = accounts_init.record_hashes();
        *self.init_sm.write().unwrap() = Some(accounts_init);

        let accounts_result = AccountsResultSM::new(init_state.clone(), final_state.clone(), poseidon.clone());
        let result_hash = accounts_result.record_hashes();
        *self.result_sm.write().unwrap() = Some(accounts_result);

        (init_hash, result_hash)
    }

    pub fn plan(&self, metrics: &mut HashMap<usize, Vec::<(ChunkId, Box<dyn BusDeviceMetrics>)>>) -> Vec<(usize, Vec<Plan>)> {
        vec![
            (ACCOUNTS_INIT_ID, self.init_sm.read().unwrap().as_ref().unwrap().build_planner().plan(metrics.remove(&ACCOUNTS_INIT_ID).unwrap())),
            (ACCOUNTS_RESULT_ID, self.result_sm.read().unwrap().as_ref().unwrap().build_planner().plan(metrics.remove(&ACCOUNTS_RESULT_ID).unwrap())),
            (PERMUTER_ID, self.poseidon_sm.read().unwrap().as_ref().unwrap().build_planner().plan(metrics.remove(&PERMUTER_ID).unwrap())),
        ]
    }

    pub fn build_instance(&self, ictx: InstanceCtx) -> BuiltInstance<F> {
        let airgroup_id = ictx.plan.airgroup_id;
        let air_id = ictx.plan.air_id;

        if airgroup_id != ZISK_AIRGROUP_ID {
            panic!("Unsupported AIR group ID: {}", airgroup_id);
        }

        if air_id == ACCOUNTS_INIT_AIR_IDS[0] {
            BuiltInstance::Built(self.init_sm.read().unwrap().as_ref().unwrap().build_instance(ictx))
        } else if air_id == ACCOUNTS_RESULT_AIR_IDS[0] {
            BuiltInstance::Built(self.result_sm.read().unwrap().as_ref().unwrap().build_instance(ictx))
        } else if air_id == POSEIDON_PERMUTER_AIR_IDS[0] {
            BuiltInstance::Built(self.poseidon_sm.read().unwrap().as_ref().unwrap().build_instance(ictx))
        } else {
            BuiltInstance::NotRecognized(ictx)
        }
    }

    pub fn build_counters(&self) -> (AccountsInitCounter, AccountsResultCounter) {
        (
            self.init_sm.read().unwrap().as_ref().unwrap().build_counter(),
            self.result_sm.read().unwrap().as_ref().unwrap().build_counter()
        )
    }
}
