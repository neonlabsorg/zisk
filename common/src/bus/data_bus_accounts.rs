use super::BusId;

pub const ACCOUNTS_BUS_ID: BusId = BusId(3);
pub const ACCOUNTS_BUS_DATA_SIZE: usize = 4;

pub type AccountsData = [u64; ACCOUNTS_BUS_DATA_SIZE];

pub struct AccountsBusData;

pub const ACCOUNTS_INIT_DATA_TYPE: u64 = 0;
pub const ACCOUNTS_RESULT_DATA_TYPE: u64 = 1;

impl AccountsBusData {
    pub fn new(addr: u64, vals: [u64; 2], val_type: u64) -> AccountsData {
        [addr, vals[0], vals[1], val_type]
    }

    #[inline(always)]
    pub fn get_addr(data: &[u64]) -> u32 {
        data[0] as u32
    }
    
    #[inline(always)]
    pub fn values(data: &[u64]) -> [u64; 2] {
        [data[1], data[2]]
    }

    pub fn val_type(data: &[u64]) -> u64 {
        data[3]
    }
}
