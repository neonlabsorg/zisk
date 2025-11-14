use std::{collections::BTreeMap, sync::{atomic::AtomicBool, Arc, Mutex}};

use mem_common::{MemHelpers, MEM_BYTES};
use fields::PrimeField64;
use proofman_common::{AirInstance, FromTrace};
use sbpf_parser::mem::TxInput;
use sm_mem::Mem;
use zisk_common::{BusDevice, BusDeviceMetrics, CheckPoint, ChunkId, ComponentBuilder, Instance, InstanceCtx, InstanceType, MemBusData, MemCollectorInfo, Plan, Planner, MEM_BUS_ID};
use zisk_pil::{AccountsResultTrace, AccountsResultTraceRow, ACCOUNTS_RESULT_AIR_IDS, ZISK_AIRGROUP_ID};

use crate::poseidon::{PoseidonSM, POSEIDON_BITRATE, POSEIDON_WIDTH};

#[derive(Clone)]
struct AccountsResultStats(Arc<BTreeMap<u64, Mutex<Option<(u64, [u32; 2])>>>>);

#[derive(Clone)]
pub struct AccountsResultSM<F: PrimeField64> {
    initial_state: Arc<TxInput>,
    final_state: Arc<TxInput>,
    stats: AccountsResultStats,
    poseidon: PoseidonSM<F>
}

impl<F: PrimeField64> AccountsResultSM<F> {
    pub fn new(initial_state: Arc<TxInput>, final_state: Arc<TxInput>, poseidon: PoseidonSM<F>) -> Self {
        let mut writes = BTreeMap::new();

        for addr in final_state.iter() {
            writes.insert(addr, None.into());
        }

        Self {
            initial_state,
            final_state,
            stats: AccountsResultStats(writes.into()),
            poseidon
        }
    }

    pub fn record_hashes(&self) -> [F; POSEIDON_BITRATE] {
        let mut hash_input = [F::ZERO; POSEIDON_WIDTH];
        for (_i, addr) in self.final_state.iter().enumerate() {
            let val = self.final_state.read(addr).unwrap_or(0);
            let val = [F::from_u32(val as u32), F::from_u32((val >> 32) as u32)];

            let input = [F::from_u64(addr / MEM_BYTES), val[0].into(), val[1].into(), F::ZERO];
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
        let mut trace = AccountsResultTrace::<F>::new_from_vec(trace_buffer);

        let mut row = 0;
        let mut hash_input = [F::ZERO; POSEIDON_WIDTH];
        for (i, addr) in self.final_state.iter().enumerate() {
            trace[i].addr = F::from_u64(addr / MEM_BYTES);
            let val = self.final_state.read(addr).unwrap_or(0);
            let val = [F::from_u32(val as u32), F::from_u32((val >> 32) as u32)];
            trace[i].val = val.clone();

            let val_init = self.initial_state.read(addr).unwrap_or(0);
            let val_init = [val_init as u32, (val_init >> 32) as u32];
            trace[i].val_init = val_init.map(F::from_u32);

            let vals = self.stats.0.get(&addr).unwrap().lock().unwrap().clone();
            trace[i].sel_wr = F::from_bool(vals.is_some());
            trace[i].val_wr = vals.map_or([F::ZERO; 2], |x| x.1.map(F::from_u32));
            if vals.is_some() {
                //println!("write on row #{i} at witness generation {addr} {val_init:?} -> {:?} but actual val is {val:?}", vals.1);
                assert!(trace[i].val_wr == val);
            } else {
                assert!(val.map(|x| x.to_unique_u64() as u32) == val_init, "unexpected write on row #{i} at witness generation {addr} {val_init:?} -> {:?}", val);
            }

            hash_input = self.poseidon.permute(&hash_input, &[F::from_u64(addr / MEM_BYTES), val[0].into(), val[1].into(), F::ZERO]);
            trace[i].hash_accum = hash_input.clone();
            trace[i].sel = F::ONE;

            row += 1;
        }
        tracing::info!(
            "··· Creating Result mem [{} / {} rows filled {:.2}%]",
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

    pub fn build_counter(&self) -> AccountsResultCounter {
        AccountsResultCounter {
            stats: self.stats.clone()
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
            None,
            1
        )]
    }
}



impl<F: PrimeField64> ComponentBuilder<F> for AccountsResultSM<F> {
    fn build_planner(&self) -> Box<dyn zisk_common::Planner> {
        Box::new(AccountsResultPlanner)
    }

    fn build_counter(&self) -> Option<Box<dyn BusDeviceMetrics>> {
        None
    }

    fn build_instance(&self, ictx: InstanceCtx) -> Box<dyn Instance<F>> {
        Box::new(AccountsResultInstance { 
            ictx,
            sm: self.clone()
        })
    }
}

struct AccountsResultInstance<F: PrimeField64> {
    ictx: InstanceCtx,

    sm: AccountsResultSM<F>
}


impl<F: PrimeField64> Instance<F> for AccountsResultInstance<F> {
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
        self.sm.compute_witness(trace_buffer)
    }


    fn build_inputs_collector(
            &self,
            _chunk_id: ChunkId,
        ) -> Option<Box<dyn BusDevice<zisk_common::PayloadType>>> {
        Some(Box::new(AccountsResultCounter{ stats: self.sm.stats.clone() }))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub struct AccountsResultCounter {
    stats: AccountsResultStats
}

impl BusDevice<u64> for AccountsResultCounter {
    fn bus_id(&self) -> Vec<zisk_common::BusId> {
        vec![MEM_BUS_ID]
    }

    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    fn process_data(
            &mut self,
            bus_id: &zisk_common::BusId,
            data: &[u64],
            _pending: &mut std::collections::VecDeque<(zisk_common::BusId, Vec<u64>)>,
            _mem_collector_info: Option<&[MemCollectorInfo]>,
        ) -> bool {
        debug_assert!(*bus_id == MEM_BUS_ID);

        if MemHelpers::is_write(MemBusData::get_op(data)) {
            let bytes = MemBusData::get_bytes(data);
            let addr = MemBusData::get_addr(data);
            let value = MemBusData::get_value(data);
            let read_values = MemBusData::get_mem_values(data);
            let new_step = MemBusData::get_step(data);

            let update = |addr, val: u64| {
                if let Some(vals) = self.stats.0.get(addr) {
                    let new_vals = [val as u32, (val >> 32) as u32];
                    //println!("detected write to {addr} with {val} {new_vals:?}");
                    let mut vals = vals.lock().unwrap();
                    *vals = match *vals {
                        Some((step, memvals)) => if step < new_step { 
                            Some((new_step, new_vals))
                        } else {
                            Some((step, memvals))
                        },
                        None => Some((new_step, new_vals))
                    };
                }
            };
            let (reqaddr1, reqaddr2) = zisk_core::Mem::required_addresses(addr, bytes as u64);
            let [wr1, wr2] = MemHelpers::get_write_values(addr, bytes, value, read_values);
            //println!("collecting {addr}={value} of size {bytes} | {read_values:?} collecting debug required addresses {reqaddr1} {reqaddr2} = {wr1} {wr2}");
            if MemHelpers::is_double(addr, bytes) {
                update(&reqaddr1, wr1);
                update(&reqaddr2, wr2);
                assert!(reqaddr1 != reqaddr2);
            } else {
                update(&reqaddr1, wr1);
                assert!(reqaddr1 == reqaddr2);
            }


        }

        true
    }
}
