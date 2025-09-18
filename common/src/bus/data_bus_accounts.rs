use super::BusId;

pub const ACCOUNTS_INIT_BUS_ID: BusId = BusId(3);
pub const ACCOUNTS_INIT_BUS_DATA_SIZE: usize = 3;

pub type AccountsInitData = [u64; ACCOUNTS_INIT_BUS_DATA_SIZE];

pub struct AccountsInitBusData;

impl AccountsInitBusData {
    pub fn new(addr: u64, vals: [u64; 2]) -> AccountsInitData {
        [addr, vals[0], vals[1]]
    }

    #[inline(always)]
    pub fn get_addr(data: &[u64]) -> u32 {
        data[0] as u32
    }
    
    #[inline(always)]
    pub fn values(data: &[u64]) -> [u64; 2] {
        [data[1], data[2]]
    }
}

pub const ACCOUNTS_RESULT_BUS_ID: BusId = BusId(3);
pub const ACCOUNTS_RESULT_BUS_DATA_SIZE: usize = 4;

pub type AccountsResultData = [u64; ACCOUNTS_RESULT_BUS_DATA_SIZE];

pub struct AccountsResultBusData;

impl AccountsResultBusData {
    pub fn new(addr: u64, vals: [u64; 2]) -> AccountsInitData {
        [addr, vals[0], vals[1]]
    }

    #[inline(always)]
    pub fn get_addr(data: &[u64]) -> u32 {
        data[0] as u32
    }
    
    #[inline(always)]
    pub fn values(data: &[u64]) -> [u64; 2] {
        [data[1], data[2]]
    }

    pub fn step(data: &[u64]) -> u64 {
        data[3]
    }
}
