use std::sync::Arc;

use fields::{Field, Goldilocks, PrimeField64};

const POSEIDON_BITRATE: usize = 4;
pub const POSEIDON_WIDTH: usize = 12;
const POSEIDON_SUBWORDS: usize = 7;

struct PoseidonPermuter {
    arc: [u64; POSEIDON_WIDTH],
    mix: [[u64; POSEIDON_WIDTH]; POSEIDON_WIDTH],
    partial_rounds: usize,
    full_rounds: usize
}

impl Default for PoseidonPermuter {
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
            ],
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
            ],
            partial_rounds: 57,
            full_rounds: 12
        }
    }
}

impl PoseidonPermuter {
    fn round(&self, state: &[Goldilocks; POSEIDON_WIDTH], partial: bool) -> [Goldilocks; POSEIDON_WIDTH] {
        let mut before_mix = [Goldilocks::ZERO; POSEIDON_WIDTH];

        for i in 0..POSEIDON_WIDTH {
            before_mix[i] = state[i] + Goldilocks::from_u64(self.arc[i]);
        }

        let lim = if partial { 1 } else { POSEIDON_WIDTH };
        for i in 0..lim {
            let mut accum = before_mix[i];
            for _ in 0..POSEIDON_SUBWORDS {
                accum *= before_mix[i];
            }
            before_mix[i] = accum;
        }

        let mut mixed = [Goldilocks::ZERO; POSEIDON_WIDTH];
        for i in 0..POSEIDON_WIDTH {
            for j in 0..POSEIDON_WIDTH {
                mixed[i] += Goldilocks::from_u64(self.mix[i][j]) * before_mix[j];
            }
        }

        mixed
    }

    pub fn permute(&self, state: &[u64; POSEIDON_WIDTH]) -> [u64; POSEIDON_WIDTH] {
        let mut state = state.map(|x| Goldilocks::from_u64(x));
        for _ in 0..self.full_rounds {
            state = self.round(&state, false);
        }
        for _ in 0..self.partial_rounds {
            state = self.round(&state, true);
        }
        for _ in 0..self.full_rounds {
            state = self.round(&state, false);
        }
        state.map(|x| x.to_unique_u64())
    }

    pub fn mix_to_state(&self, state: &[u64; POSEIDON_WIDTH], input: &[u64; POSEIDON_BITRATE]) -> [u64; POSEIDON_WIDTH] {
        let mut res_state = state.map(|x| Goldilocks::from_u64(x));
        for i in 0..POSEIDON_BITRATE {
            res_state[i] += Goldilocks::from_u64(input[i]);
        }

        res_state.map(|x| x.to_unique_u64())
    }
}

pub struct PoseidonSM {
    permuter: Arc<PoseidonPermuter>,
    input_rows: Arc<std::sync::RwLock<Vec<[u64; POSEIDON_WIDTH]>>>
}

impl PoseidonSM {
    pub fn new() -> Self {
        Self{
            permuter: PoseidonPermuter::default().into(),
            input_rows: Arc::new(vec![].into())
        }
    }

    pub fn permute(&self, state: &[u64; POSEIDON_WIDTH], input: &[u64; POSEIDON_BITRATE]) -> [u64; POSEIDON_WIDTH] {
        let mixed = self.permuter.mix_to_state(state, input);
        self.input_rows.write().expect("failed to take poseidon input lock").push(mixed.clone());
        self.permuter.permute(&mixed)
    }

}
