use std::sync::Arc;

use fields::{Goldilocks, PrimeField64};
use proofman_common::AirInstance;
use zisk_common::{BusDeviceMetrics, CheckPoint, ChunkId, ComponentBuilder, Instance, InstanceCtx, InstanceType, Plan};
use zisk_pil::{PoseidonPermuterTrace, POSEIDON_PERMUTER_AIR_IDS, ZISK_AIRGROUP_ID};

pub const POSEIDON_BITRATE: usize = 4;
pub const POSEIDON_WIDTH: usize = 12;
const POSEIDON_SUBWORDS: usize = 7;

pub const POSEIDON_CHUNK_SIZE: usize = 2_usize.pow(21_u32);

#[derive(Clone)]
pub struct PoseidonPermuter<F: PrimeField64> {
    arc: [F; POSEIDON_WIDTH],
    mix: [[F; POSEIDON_WIDTH]; POSEIDON_WIDTH],
    partial_rounds: usize,
    full_rounds: usize
}

impl Default for PoseidonPermuter<Goldilocks> {
    fn default() -> Self {
        Self {
            mix: [
                [25, 15, 41, 16, 2, 28, 13, 13, 39, 18, 34, 20],
                [20, 17, 15, 41, 16, 2, 28, 13, 13, 39, 18, 34],
                [34, 20, 17, 15, 41, 16,  2, 28, 13, 13, 39, 18],
                [18, 34, 20, 17, 15, 41, 16,  2, 28, 13, 13, 39],
                [39, 18, 34, 20, 17, 15, 41, 16,  2, 28, 13, 13],
                [13, 39, 18, 34, 20, 17, 15, 41, 16,  2, 28, 13],
                [13, 13, 39, 18, 34, 20, 17, 15, 41, 16,  2, 28],
                [28, 13, 13, 39, 18, 34, 20, 17, 15, 41, 16,  2],
                [2, 28, 13, 13, 39, 18, 34, 20, 17, 15, 41, 16],
                [16,  2, 28, 13, 13, 39, 18, 34, 20, 17, 15, 41],
                [41, 16,  2, 28, 13, 13, 39, 18, 34, 20, 17, 15],
                [15, 41, 16,  2, 28, 13, 13, 39, 18, 34, 20, 17],
            ].map(|x| x.map(Goldilocks::from_u64)),
            arc: [
                3014888795719246729,
                5963864597674384598,
                2768803421146185923,
                18185368981409310590,
                13796279610465360307,
                13258428655399477418,
                6311108545355074403,
                9091478136808910551,
                5657164823329005273,
                14773843000339061443,
                5277400092504871362,
                6244933830025130194
            ].map(Goldilocks::from_u64),
            partial_rounds: 57,
            full_rounds: 12
        }
    }
}

impl<F: PrimeField64> PoseidonPermuter<F> {
    fn hash_rows(&self) -> usize {
        self.full_rounds * 2 + self.partial_rounds
    }

    fn segment_size(&self) -> usize {
        POSEIDON_CHUNK_SIZE / self.hash_rows()
    }

    fn add_arc(&self, state: &[F; POSEIDON_WIDTH]) -> [F; POSEIDON_WIDTH] {
        let mut result = state.clone();
        for i in 0..POSEIDON_WIDTH {
            result[i] = state[i] + self.arc[i];
        }
        result
    }

    fn subwords(&self, state: &[F; POSEIDON_WIDTH], partial: bool) -> [F; POSEIDON_WIDTH] {
        let mut result = state.clone();
        let lim = if partial { 1 } else { POSEIDON_WIDTH };
        for i in 0..lim {
            let mut accum = state[i];
            for _ in 0..POSEIDON_SUBWORDS-1 {
                accum *= state[i];
            }
            result[i] = accum;
        }
        result
    }

    fn mix(&self, state: &[F; POSEIDON_WIDTH]) -> [F; POSEIDON_WIDTH] {
        let mut mixed = [F::ZERO; POSEIDON_WIDTH];
        for i in 0..POSEIDON_WIDTH {
            for j in 0..POSEIDON_WIDTH {
                mixed[i] += self.mix[i][j] * state[j];
            }
        }
        mixed
    }

    fn round(&self, state: &[F; POSEIDON_WIDTH], partial: bool) -> [F; POSEIDON_WIDTH] {
        let mut before_mix = [F::ZERO; POSEIDON_WIDTH];

        for i in 0..POSEIDON_WIDTH {
            before_mix[i] = state[i] + self.arc[i];
        }

        let lim = if partial { 1 } else { POSEIDON_WIDTH };
        for i in 0..lim {
            let mut accum = before_mix[i];
            for _ in 0..POSEIDON_SUBWORDS-1 {
                accum *= before_mix[i];
            }
            before_mix[i] = accum;
        }

        self.mix(&before_mix)
    }

    pub fn permute(&self, state: &[F; POSEIDON_WIDTH]) -> [F; POSEIDON_WIDTH] {
        let mut state = state.clone();
        for _ in 1..self.full_rounds {
            state = self.round(&state, false);
        }
        for _ in 0..self.partial_rounds {
            state = self.round(&state, true);
        }
        for _ in 0..self.full_rounds {
            state = self.round(&state, false);
        }
        state
    }

    pub fn output(&self, state: &[F; POSEIDON_WIDTH]) -> [F; POSEIDON_BITRATE] {
        let mut result = [F::ZERO; POSEIDON_BITRATE];
        for i in 0..POSEIDON_BITRATE {
            result[i] = state[i];
        }
        result
    }

    pub fn mix_to_state(&self, state: &[F; POSEIDON_WIDTH], input: &[F; POSEIDON_BITRATE]) -> [F; POSEIDON_WIDTH] {
        let mut res_state = state.clone();
        for i in 0..POSEIDON_BITRATE {
            res_state[i] += input[i];
        }

        res_state
    }
}

#[derive(Clone)]
pub struct PoseidonSM<F: PrimeField64> {
    permuter: Arc<PoseidonPermuter<F>>,
    input_rows: Arc<std::sync::RwLock<Vec<[F; POSEIDON_WIDTH]>>>
}

impl<F: PrimeField64> PoseidonSM<F> {
    pub fn new(permuter: PoseidonPermuter<F>) -> Self {
        Self{
            permuter: permuter.into(),
            input_rows: Arc::new(vec![].into())
        }
    }

    pub fn record_first(&self, input: &[F; POSEIDON_BITRATE]) {
        self.record(&[F::ZERO; POSEIDON_WIDTH], input);
    }

    pub fn output(&self, state: &[F; POSEIDON_WIDTH]) -> [F; POSEIDON_BITRATE] {
        self.permuter.output(state)
    }

    pub fn record(&self, state: &[F; POSEIDON_WIDTH], input: &[F; POSEIDON_BITRATE]) {
        let mixed = self.permuter.mix_to_state(state, input);
        self.input_rows.write().expect("failed to take poseidon input lock").push(mixed.clone());
    }

    pub fn permute(&self, state: &[F; POSEIDON_WIDTH], input: &[F; POSEIDON_BITRATE]) -> [F; POSEIDON_WIDTH] {
        let mixed = self.permuter.mix_to_state(state, input);
        self.permuter.permute(&mixed)
    }
}


impl<F: PrimeField64> ComponentBuilder<F> for PoseidonSM<F> {
    fn build_planner(&self) -> Box<dyn zisk_common::Planner> {
        let segment_size = self.permuter.segment_size();
        let segments_count = 1 + (self.input_rows.read().unwrap().len() - 1) / segment_size;
        Box::new(PoseidonPlanner { segment_size, segments_count })
    }

    fn build_counter(&self) -> Option<Box<dyn BusDeviceMetrics>> {
        None
    }

    fn build_instance(&self, ictx: InstanceCtx) -> Box<dyn Instance<F>> {
        Box::new(PoseidonInstance { 
            ictx,
            sm: self.clone()
        })
    }
}


struct PoseidonInstance<F: PrimeField64> {
    ictx: InstanceCtx,
    sm: PoseidonSM<F>
}

impl<F: PrimeField64> zisk_common::Instance<F> for PoseidonInstance<F> {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

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
        let mut trace = PoseidonPermuterTrace::<F>::new_from_vec(trace_buffer);

        let mut row = 0;
        let first_row = self.ictx.plan.segment_id.unwrap().0 * self.sm.permuter.segment_size();

        for (_i, input) in self.sm.input_rows.read().unwrap()[first_row..].iter().take(self.sm.permuter.segment_size()).enumerate() {
            let output = self.sm.permuter.permute(input);
            let mut state = [F::ZERO; POSEIDON_WIDTH];
            for j in 0..self.sm.permuter.full_rounds {
                //6
                trace[row].input = input.clone();
                trace[row].last_round = F::ZERO;
                trace[row].first_round = F::ZERO;
                trace[row].round = F::from_usize(j);
                trace[row].full_round = F::ONE;
                trace[row].b = self.sm.permuter.add_arc(&state);
                trace[row].c = self.sm.permuter.subwords(&trace[row].b, false);
                trace[row].d = self.sm.permuter.mix(&trace[row].c);

                if j == 0 {
                    trace[row].first_round = F::ONE;
                    state = input.clone();
                } else {
                    assert_eq!(self.sm.permuter.round(&state, false), trace[row].d);
                    state = trace[row].d.clone();
                }
                trace[row].state = state.clone();

                row += 1;
            }

            for j in 0..self.sm.permuter.partial_rounds {
                trace[row].input = input.clone();
                trace[row].last_round = F::ZERO;
                trace[row].first_round = F::ZERO;
                trace[row].round = F::from_usize(j + self.sm.permuter.full_rounds);
                trace[row].full_round = F::ZERO;
                trace[row].b = self.sm.permuter.add_arc(&state);
                trace[row].c = self.sm.permuter.subwords(&trace[row].b, true);
                trace[row].d = self.sm.permuter.mix(&trace[row].c);

                state = self.sm.permuter.round(&state, true);
                assert_eq!(state, trace[row].d);
                trace[row].state = state.clone();

                row += 1;
            }

            for j in 0..self.sm.permuter.full_rounds {
                trace[row].input = input.clone();
                trace[row].last_round = F::ZERO;
                trace[row].first_round = F::ZERO;
                trace[row].round = F::from_usize(j + self.sm.permuter.full_rounds + self.sm.permuter.partial_rounds);
                trace[row].full_round = F::ONE;
                trace[row].b = self.sm.permuter.add_arc(&state);
                trace[row].c = self.sm.permuter.subwords(&trace[row].b, false);
                trace[row].d = self.sm.permuter.mix(&trace[row].c);

                state = self.sm.permuter.round(&state, false);
                assert_eq!(state, trace[row].d);
                trace[row].state = state.clone();

                row += 1;
            }
            assert!(trace[row - 1].state == output);
            trace[row - 1].last_round = F::ONE;
        }

        tracing::info!(
            "··· Posedon permuter [{} / {} rows filled {:.2}%]",
            row,
            trace.num_rows(),
            row as f64 / trace.num_rows() as f64 * 100.0
        );

        if row < trace.num_rows() {
            trace[row].input = [F::ZERO; POSEIDON_WIDTH];
            trace[row].last_round = F::ZERO;
            trace[row].first_round = F::ONE;
            trace[row].round = F::ZERO;
            trace[row].full_round = F::ONE;
            trace[row].state = [F::ZERO; POSEIDON_WIDTH];
            trace[row].b = self.sm.permuter.add_arc(&trace[row].state);
            trace[row].c = self.sm.permuter.subwords(&trace[row].b, false);
            trace[row].d = self.sm.permuter.mix(&trace[row].c);
        }

        for i in row..trace.num_rows() {
            trace[i] = trace[row].clone();
        }

        Some(AirInstance::new_from_trace(proofman_common::FromTrace::new(&mut trace)))
    }

    fn build_inputs_collector(
            &self,
            _chunk_id: ChunkId,
        ) -> Option<Box<dyn zisk_common::BusDevice<zisk_common::PayloadType>>> 
    {
        None
    }

}

struct PoseidonPlanner {
    segment_size: usize,
    segments_count: usize
}

impl zisk_common::Planner for PoseidonPlanner {
    fn plan(&self, metrics: Vec<(zisk_common::ChunkId, Box<dyn BusDeviceMetrics>)>) -> Vec<zisk_common::Plan> {
        let vec_chunk_ids = metrics.iter().map(|(chunk_id, _)| *chunk_id).collect::<Vec<_>>();
        (0..self.segments_count)
            .map(|segment|
               Plan::new(
                    ZISK_AIRGROUP_ID,
                    POSEIDON_PERMUTER_AIR_IDS[0],
                    Some(zisk_common::SegmentId(segment)),
                    zisk_common::InstanceType::Instance,
                    CheckPoint::Multiple(vec_chunk_ids.clone()),
                    None,
                    self.segment_size,
                ))
            .collect()
    }
}
