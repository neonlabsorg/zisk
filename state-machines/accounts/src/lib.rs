use fields::{Goldilocks, PrimeField64};
use zisk_common::ComponentBuilder;
use init::{AccountsInitCounter, AccountsInitSM};
use poseidon::{PoseidonPermuter, PoseidonSM};
use result::{AccountsResultCounter, AccountsResultSM};
use sbpf_parser::mem::TxInput;
use zisk_common::{BusDeviceMetrics, ChunkId, Plan};
use std::sync::{Arc, RwLock};

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

impl<F: PrimeField64> AccountsSMBundle<F> {
    pub fn new(poseidon_permuter: PoseidonPermuter<F>) -> Self {
        Self {
            init_sm: Arc::new(None.into()),
            result_sm: Arc::new(None.into()),
            poseidon_sm: Arc::new(None.into()),
            poseidon_permuter
        }
    }

    pub fn initialize(&self, init_state: Arc<TxInput>, final_state: Arc<TxInput>) {
        let poseidon = PoseidonSM::new(self.poseidon_permuter.clone());
        *self.poseidon_sm.write().unwrap() = Some(poseidon.clone());

        let accounts_init = AccountsInitSM::new(init_state.clone(), poseidon.clone());
        accounts_init.record_hashes();
        *self.init_sm.write().unwrap() = Some(accounts_init);

        let accounts_result = AccountsResultSM::new(init_state.clone(), final_state.clone(), poseidon.clone());
        accounts_result.record_hashes();
        *self.result_sm.write().unwrap() = Some(accounts_result);

    }

    pub fn plan(&self, mut it: impl Iterator<Item = Vec<(ChunkId, Box<dyn BusDeviceMetrics>)>>) -> Vec<Vec<Plan>> {
        vec![
            self.init_sm.read().unwrap().as_ref().unwrap().build_planner().plan(it.next().unwrap()),
            self.result_sm.read().unwrap().as_ref().unwrap().build_planner().plan(it.next().unwrap()),
            self.poseidon_sm.read().unwrap().as_ref().unwrap().build_planner().plan(vec![]),
        ]
    }

    pub fn build_instances(&self) {
    }

    pub fn build_counters(&self) -> (AccountsInitCounter, AccountsResultCounter) {
        (
            self.init_sm.read().unwrap().as_ref().unwrap().build_counter(),
            self.result_sm.read().unwrap().as_ref().unwrap().build_counter()
        )
    }
}
