//! Zisk ROM
//!
//! # ROM data
//!
//! The Zisk ROM contains the result of parsing a RISC-V ELF program file data, and then keeping the
//! data that is required to execute any input data against this program using the Zisk processor.
//! This information consists on the following data:
//!
//! ## Zisk instructions
//!
//! * Created by transpiling the RISC-V instructions
//! * Every RISC-V instruction can generate a different number of Zisk instructions: 1 (in most of
//!   the cases), 2, 3 or 4 (e.g. in instruction containing some atomic operations).
//! * For this reason, Zisk instructions addresses are normally spaced 4 units (e.g. 4096, 4100,
//!   4104...) leaving room for up to 3 additional Zisk instructions if needed to fulfill the
//!   original RISC-V instruction they represent.
//! * This way, RISC-V jumps can conveniently be mapped to Zisk jumps by multiplying their relative
//!   offsets by 4.
//! * The Zisk instructions are stored in a map using the pc as the key
//!
//! ## Read-only (RO) data
//!
//! * RISC-V programs can contain some data that is required to execute the program, e.g. constants.
//! * There can be several sections of RO memory-mapped data in the same RISC-V program, so we need
//!   to store a list of them as part of the ROM.
//! * There can be none, one, or several.
//!
//! # Fetching instructions
//!
//! * During the Zisk program execution, the Zisk Emulator must fetch the Zisk instruction
//!   corresponding to the current pc for every execution step.
//! * This fetch can be expensive in terms of computational time if done directly using the map.
//! * For this reason, the original map of instructions is split into 3 different containers that
//!   allow to speed-up the process of finding the Zisk instruction that matches a specific pc
//!   addresss.
//! * The logic of this fetch procedure can be seen in the method `get_instruction()`.  This method
//!   searches for the Zisk instruction in 3 different containers:
//!   * If the address is >= `ROM_ADDR`, there can be 2 cases:
//!     * If the address is alligned to 4 bytes, then get it from the vector `rom_instructions`,
//!       using as index `(pc-ROM_ADDR)/4`
//!     * If the address is not allgined, then get it from the vector `rom_na_instructions`, using
//!       as index `(pc-ROM_ADDR)`
//!   * If the address is < ROM_ADDR, then get it from the vector `rom_entry_instructions`, using as
//!     index `(pc-ROM_ENTRY)/4`
use std::{collections::BTreeMap, path::PathBuf};

use crate::mem::ROM_ADDR;

use fields::PrimeField64;
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use solana_sbpf::ebpf;
use solana_sbpf::program::SBPFVersion;
use solana_sbpf::vm::Config;
use zisk_pil::MainTraceRow;

use crate::{ZiskInst, ZiskInstBuilder, FRAME_REGS_START, ROM_ENTRY, ROM_EXIT};

use sbpf_parser::elf::{load_elf, ProcessedElf};
use sbpf_parser::elf::{LoadEnv, load_elf_from_path};
use solana_sdk::account::Account;
use serde_with::{serde_as, DisplayFromStr};

const TRANSLATE_REG: u64 = 2;
const FRAME_REGS_PTR: u64 = 3;
const BASE_REG: u64 = 4;
const STORE_REG: u64 = BASE_REG + 12;
const SCRATCH_REG: u64 = STORE_REG + 12;
const SCRATCH_REG2: u64 = SCRATCH_REG + 1;
const CU_METER_REG: u64 = SCRATCH_REG2 + 1;
const TRANSPILE_ALIGN: i32 = 20;

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
struct AccountInventoryItem {
    #[serde_as(as = "DisplayFromStr")]
    pub key: Pubkey,
    pub writable: bool,
    pub file: String,
    /// lamports in the account
    pub lamports: u64,
    /// the program that owns this account. If executable, the program that loads this account.
    #[serde_as(as = "DisplayFromStr")]
    pub owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    pub executable: bool,
    /// the epoch at which this account will next owe rent
    #[serde(default)]
    pub rent_epoch: u64,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
struct AccountInventory {
    pub accounts: Vec<AccountInventoryItem>,
    pub syscalls_stubs: String,
    #[serde_as(as = "DisplayFromStr")]
    pub main_program: Pubkey
}

/// Unlike the original is sbpf's instruction translating container 
#[derive(Debug, Clone, Default)]
pub struct ZiskRom {
    pub key: Pubkey,
    pub transpiled_instructions: Vec<Vec<ZiskInst>>,
    pub system_instructions: Vec<Vec<ZiskInst>>,
    program: ProcessedElf,
    end_insts: Vec<ZiskInst>
}

pub fn reg_for_bpf_reg(reg: u8) -> u64 {
    BASE_REG + reg as u64
}

fn ireg_for_bpf_reg(reg: u8) -> i64 {
    (BASE_REG + reg as u64) as i64
}

type PcCallMap = BTreeMap<u32, u64>;

/// ZisK ROM implementation
impl ZiskRom {
    pub fn ro_sections(&self) -> impl Iterator<Item = (u64, &[u8])> {
        vec![(self.program.ro_section_vmaddr, self.program.ro_section_bytes.as_slice())].into_iter()
    }

    fn transpile_op(op: &solana_sbpf::ebpf::Insn, pc: u64, translate_pc_routine: u64, version: &SBPFVersion, config: &Config, call_map: &PcCallMap) -> Vec<ZiskInst> {
        use solana_sbpf::ebpf::*;
        //indirection modifiers
        let (width, mask) = if version.move_memory_instruction_classes() {
            match op.opc & 0xB0 {
                BPF_1B => (1, (1_u64 << 8) - 1),
                BPF_2B => (2, (1_u64 << 16) - 1),
                BPF_4B => (4, (1_u64 << 32) - 1),
                BPF_8B | _ => (8, !0_u64),
            }
        } else {
            match op.opc & 0x18 {
                BPF_W => (4, (1_u64 << 32) - 1),
                BPF_B => (1, (1_u64 << 8) - 1),
                BPF_H => (2, (1_u64 << 16) - 1),
                BPF_DW => (8, !0_u64),
                _ => panic!("cant happen")
            }
        };

        let arith_op = if op.opc & 7 == BPF_PQR && version.enable_pqr() {
            // Operation codes -- BPF_PQR class:
            //    7         6               5                               4       3          2-0
            // 0  Unsigned  Multiplication  Product Lower Half / Quotient   32 Bit  Immediate  PQR
            // 1  Signed    Division        Product Upper Half / Remainder  64 Bit  Register   PQR
            let mask64 = 0x10;
            match op.opc & 0xC0 {
                BPF_SREM => if mask64 & op.opc != 0 { "rem" } else { "rem_w" },
                BPF_SDIV => if mask64 & op.opc != 0 { "div" } else { "div_w" },
                BPF_UREM => if mask64 & op.opc != 0 { "remu" } else { "remu_w" },
                BPF_LMUL => "mulu",
                BPF_SHMUL => "mulsuh",
                BPF_UHMUL => "muluh",
                _ => ""
            }
        } else {
            // For arithmetic (BPF_ALU/BPF_ALU64_STORE) and jump (BPF_JMP) instructions:
            // +----------------+--------+--------+
            // |     4 bits     |1 b.|   3 bits   |
            // | operation code | src| insn class |
            // +----------------+----+------------+
            // (MSB)                          (LSB)
            let cls = op.opc & 0x7;
            match 0xF0 & op.opc {
                BPF_ADD => if cls == BPF_ALU32_LOAD { "add_w" } else { "add" },
                BPF_SUB => if cls == BPF_ALU32_LOAD { "sub_w" } else { "sub" },
                BPF_MUL => if cls == BPF_ALU32_LOAD { "mul_w" } else { "mul" },
                BPF_DIV /*| BPF_UDIV*/ => if cls == BPF_ALU32_LOAD { "divu_w" } else { "divu" },
                BPF_OR => "or",
                BPF_AND => "and",
                BPF_LSH => if cls == BPF_ALU32_LOAD { "sll_w" } else { "sll" },
                BPF_RSH => if cls == BPF_ALU32_LOAD { "srl_w" } else { "srl" },
                // neg not handled like arith
                BPF_MOD => if cls == BPF_ALU32_LOAD { "remu_w" } else { "remu" },
                BPF_XOR => "xor",
                // mov not handled like arith
                BPF_ARSH => if cls == BPF_ALU32_LOAD { "sra_w" } else { "sra" },
                // END (endianness) not handled like arith
                // BPF_HOR also not handled like arith
                _ => ""
            }
        };
        
        let load_impl = if op.off < 0 {
            vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op("copyb").unwrap();
                    builder.j(1, 1);
                    builder.comment("load for negative offset");
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(pc + 1);
                    builder.src_a("reg", SCRATCH_REG, false);
                    builder.src_b("imm", (-op.off).try_into().unwrap(), false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op("sub").unwrap();
                    builder.comment("load for negative offset");
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(pc + 2);
                    builder.src_a("reg", SCRATCH_REG, false);
                    builder.src_b("ind", 0, false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("copyb").unwrap();
                    builder.ind_width(width);
                    builder.comment("load for negative offset");
                    builder.j(TRANSPILE_ALIGN - 2, TRANSPILE_ALIGN - 2);
                    builder.i
                }
            ]
        } else {
            vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.src), false);
                    builder.src_b("ind", op.off.try_into().unwrap(), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("copyb").unwrap();
                    builder.ind_width(width);
                    builder.comment("load for positive offset");
                    builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                    builder.i
                }
            ]
        };

        let store_reg_impl = vec![
            {
                let mut builder = ZiskInstBuilder::new(pc);
                builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                builder.store("ind", op.off.into(), false, false);
                builder.op("copyb").unwrap();
                builder.ind_width(width);
                builder.comment("store reg");
                builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                builder.i
            },
        ];

        let store_imm_impl = vec![ 
            {
                let mut builder = ZiskInstBuilder::new(pc);
                builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                builder.src_b("imm", op.imm as u64, false);
                builder.store("ind", op.off.into(), false, false);
                builder.op("copyb").unwrap();
                builder.ind_width(width);
                builder.comment("store imm");
                builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                builder.i
            },
        ];

        match op.opc {
            LD_DW_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_b("imm", op.imm as u64, false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("copyb").unwrap();
                    builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                    builder.i
                },
            ],

            // BPF opcode: `ldxb dst, [src + off]` /// `dst = (src + off) as u8`.
            // BPF opcode: `ldxh dst, [src + off]` /// `dst = (src + off) as u16`.
            // BPF opcode: `ldxw dst, [src + off]` /// `dst = (src + off) as u32`.
            // BPF opcode: `ldxdw dst, [src + off]` /// `dst = (src + off) as u64`.
            LD_B_REG | LD_H_REG | LD_W_REG | LD_DW_REG if !version.move_memory_instruction_classes() => load_impl,
            LD_1B_REG | LD_2B_REG | LD_4B_REG | LD_8B_REG if version.move_memory_instruction_classes() => load_impl,

            // BPF opcode: `stb [dst + off], imm` /// `(dst + offset) as u8 = imm`.
            // BPF opcode: `sth [dst + off], imm` /// `(dst + offset) as u16 = imm`.
            // BPF opcode: `stw [dst + off], imm` /// `(dst + offset) as u32 = imm`.
            // BPF opcode: `stdw [dst + off], imm` /// `(dst + offset) as u64 = imm`.
            ST_1B_IMM | ST_2B_IMM | ST_4B_IMM | ST_8B_IMM if version.move_memory_instruction_classes() => store_imm_impl,
            ST_B_IMM | ST_H_IMM | ST_W_IMM | ST_DW_IMM if !version.move_memory_instruction_classes() => store_imm_impl,

            // BPF opcode: `stxb [dst + off], src` /// `(dst + offset) as u8 = src`.
            // BPF opcode: `stxh [dst + off], src` /// `(dst + offset) as u16 = src`.
            // BPF opcode: `stxw [dst + off], src` /// `(dst + offset) as u32 = src`.
            // BPF opcode: `stxdw [dst + off], src` /// `(dst + offset) as u64 = src`.
            ST_B_REG | ST_H_REG | ST_W_REG | ST_DW_REG if !version.move_memory_instruction_classes() => store_reg_impl,
            ST_1B_REG | ST_2B_REG | ST_4B_REG | ST_8B_REG if version.move_memory_instruction_classes() => store_reg_impl,

            // BPF opcode: `udiv32 dst, imm` /// `dst /= imm`.
            // BPF opcode: `sdiv32 dst, imm` /// `dst /= imm`.
            // BPF opcode: `div64 dst, imm` /// `dst /= imm`.
            // BPF opcode: `udiv64 dst, imm` /// `dst /= imm`.
            // BPF opcode: `sdiv64 dst, imm` /// `dst /= imm`.
            // BPF opcode: `div32 dst, imm` /// `dst /= imm`.
            // BPF opcode: `mod64 dst, imm` /// `dst %= imm`.
            // BPF opcode: `urem64 dst, imm` /// `dst %= imm`.
            // BPF opcode: `srem64 dst, imm` /// `dst %= imm`.
            // BPF opcode: `urem32 dst, imm` /// `dst %= imm`.
            // BPF opcode: `srem32 dst, imm` /// `dst %= imm`.
            // BPF opcode: `mod32 dst, imm` /// `dst %= imm`.
            // these are equivalent to zisk counterparts because we validate execution via real sbpf
            MOD32_IMM | SREM32_IMM | UREM32_IMM | UREM64_IMM | SREM64_IMM | MOD64_IMM | DIV64_IMM | UDIV64_IMM | SDIV64_IMM | UDIV32_IMM | DIV32_IMM | SDIV32_IMM |
            // BPF opcode: `add32 dst, imm` /// `dst += imm`.
            // BPF opcode: `mul32 dst, imm` /// `dst *= imm`.
            // BPF opcode: `lsh32 dst, imm` /// `dst <<= imm`.
            // BPF opcode: `rsh32 dst, imm` /// `dst >>= imm`.
            // BPF opcode: `arsh32 dst, imm` /// `dst >>= imm (arithmetic)`.
            // BPF opcode: `add64 dst, imm` /// `dst += imm`.
            // BPF opcode: `mul64 dst, imm` /// `dst *= imm`.
            // BPF opcode: `xor64 dst, imm` /// `dst ^= imm`.
            // BPF opcode: `or64 dst, imm` /// `dst |= imm`.
            // BPF opcode: `lsh64 dst, imm` /// `dst <<= imm`.
            // BPF opcode: `rsh64 dst, imm` /// `dst >>= imm`.
            // BPF opcode: `arsh64 dst, imm` /// `dst >>= imm (arithmetic)`.
            // BPF opcode: `lmul64 dst, imm` /// `dst = (dst * imm) as u64`.
            // BPF opcode: `shmul64 dst, imm` /// `dst = (dst * imm) >> 64`.
            // BPF opcode: `uhmul64 dst, imm` /// `dst = (dst * imm) >> 64`.
            UHMUL64_IMM | SHMUL64_IMM | LMUL64_IMM | ARSH64_IMM | LSH64_IMM | RSH64_IMM | OR64_IMM | XOR64_IMM | AND64_IMM | MUL64_IMM | ADD64_IMM |
            ARSH32_IMM | MUL32_IMM | RSH32_IMM | LSH32_IMM | ADD32_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst) as u64, false);
                    builder.src_b("imm", op.imm as u64, false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op(arith_op).unwrap();
                    builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                    builder.i
                },
            ],

            // BPF opcode: `div64 dst, src` /// `dst /= src`.
            // BPF opcode: `udiv64 dst, src` /// `dst /= src`.
            // BPF opcode: `sdiv64 dst, src` /// `dst /= src`.
            // BPF opcode: `div32 dst, src` /// `dst /= src`.
            // BPF opcode: `sdiv32 dst, src` /// `dst /= src`.
            // BPF opcode: `udiv32 dst, src` /// `dst /= src`.
            // BPF opcode: `urem32 dst, src` /// `dst %= src`.
            // BPF opcode: `srem32 dst, src` /// `dst %= src`.
            // BPF opcode: `mod32 dst, src` /// `dst %= src`.
            // BPF opcode: `mod64 dst, src` /// `dst %= src`.
            // BPF opcode: `urem64 dst, src` /// `dst %= src`.
            // BPF opcode: `srem64 dst, src` /// `dst %= src`.
            // these are equivalent to zisk counterparts because we validate execution via real sbpf
            MOD64_REG | MOD32_REG | SREM32_REG | UREM32_REG | UDIV32_REG | DIV64_REG | UDIV64_REG | SDIV64_REG | SDIV32_REG |
            // BPF opcode: `add32 dst, src` /// `dst += src`.
            // BPF opcode: `mul32 dst, src` /// `dst *= src`.
            // BPF opcode: `lsh32 dst, src` /// `dst <<= src`.
            // BPF opcode: `rsh32 dst, src` /// `dst >>= src`.
            // BPF opcode: `add64 dst, src` /// `dst += src`.
            // BPF opcode: `and64 dst, imm` /// `dst &= imm`.
            // BPF opcode: `mul64 dst, src` /// `dst *= src`.
            // BPF opcode: `and64 dst, src` /// `dst &= src`.
            // BPF opcode: `xor64 dst, src` /// `dst ^= src`.
            // BPF opcode: `or64 dst, src` /// `dst |= src`.
            // BPF opcode: `lsh64 dst, src` /// `dst <<= src`.
            // BPF opcode: `rsh64 dst, src` /// `dst >>= src`.
            // BPF opcode: `arsh32 dst, src` /// `dst >>= src (arithmetic)`.
            // BPF opcode: `arsh64 dst, src` /// `dst >>= src (arithmetic)`.
            // BPF opcode: `sub64 dst, src` /// `dst -= src`.
            // BPF opcode: `sub32 dst, src` /// `dst -= src`.
            // BPF opcode: `lmul64 dst, src` /// `dst = (dst * src) as u64`.
            // BPF opcode: `shmul64 dst, src` /// `dst = (dst * src) >> 64`.
            // BPF opcode: `uhmul64 dst, src` /// `dst = (dst * src) >> 64`.
            UHMUL64_REG | SHMUL64_REG | LMUL64_REG | SUB32_REG | SUB64_REG | ARSH64_REG | UREM64_REG | SREM64_REG | LSH64_REG | RSH64_REG | OR64_REG | XOR64_REG
                | AND64_REG | MUL64_REG | ADD64_REG | ARSH32_REG | LSH32_REG | RSH32_REG
                | MUL32_REG | DIV32_REG | ADD32_REG => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op(arith_op).unwrap();
                    builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                    builder.i
                },
            ],

            // BPF opcode: `sub64 dst, imm` /// `dst -= imm`.
            // BPF opcode: `sub32 dst, imm` /// `dst = imm - dst`.
            SUB32_IMM | SUB64_IMM => if version.swap_sub_reg_imm_operands() {
                // self.reg[dst] =  (insn.imm as u64).wrapping_sub(self.reg[dst])
                vec![
                    {
                        let mut builder = ZiskInstBuilder::new(pc);
                        builder.src_a("imm", op.imm as u64, false);
                        builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                        builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                        builder.op(arith_op).unwrap();
                        builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                        builder.i
                    },
                ]
            } else {
                // self.reg[dst] =  self.reg[dst].wrapping_sub(insn.imm as u64)
                vec![
                    {
                        let mut builder = ZiskInstBuilder::new(pc);
                        builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                        builder.src_b("imm", op.imm as u64, false);
                        builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                        builder.op(arith_op).unwrap();
                        builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                        builder.i
                    },
                ]
            },

            // BPF opcode: `xor32 dst, src` /// `dst ^= src`.
            // BPF opcode: `or32 dst, src` /// `dst |= src`.
            // BPF opcode: `and32 dst, src` /// `dst &= src`.
            // BPF opcode: `lmul32 dst, src` /// `dst *= (dst * src) as u32`.
            LMUL32_REG | OR32_REG | XOR32_REG | AND32_REG => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("imm", mask, false);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", ireg_for_bpf_reg(op.src), false, false);
                    builder.op("and").unwrap();
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(pc + 1);
                    builder.src_a("imm", mask, false);
                    builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("and").unwrap();
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(pc + 2);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op(arith_op).unwrap();
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(pc + 3);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("imm", mask, false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("and").unwrap();
                    builder.j(TRANSPILE_ALIGN - 3, TRANSPILE_ALIGN - 3);
                    builder.i
                }
            ],

            // BPF opcode: `or32 dst, imm` /// `dst |= imm`.
            // BPF opcode: `and32 dst, imm` /// `dst &= imm`.
            // BPF opcode: `xor32 dst, imm` /// `dst ^= imm`.
            // BPF opcode: `lmul32 dst, imm` /// `dst *= (dst * imm) as u32`.
            LMUL32_IMM | XOR32_IMM | AND32_IMM | OR32_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("imm", mask, false);
                    builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("and").unwrap();
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(pc + 1);
                    builder.src_a("imm", op.imm as u64 & mask, false);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op(arith_op).unwrap();
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(pc + 2);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("imm", mask, false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("and").unwrap();
                    builder.j(TRANSPILE_ALIGN - 2, TRANSPILE_ALIGN - 2);
                    builder.i
                }
            ],

            // BPF opcode: `hor64 dst, imm` /// `dst |= imm << 32`.
            HOR64_IMM if version.disable_lddw() => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("imm", (op.imm as u64).wrapping_shl(32), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("or").unwrap();
                    builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                    builder.i
                }
            ],

            // hopefully disabled
            // BPF opcode: `shmul32 dst, imm` /// `dst = (dst * imm) as i64`.
            // SHMUL32_IMM
            // BPF opcode: `shmul32 dst, src` /// `dst = (dst * src) as i64`.
            // SHMUL32_REG

            // BPF opcode: `mov64 dst, src` /// `dst = src`.
            MOV64_REG => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("copyb").unwrap();
                    builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                    builder.i
                }
            ],

            // BPF opcode: `mov64 dst, imm` /// `dst = imm`.
            MOV64_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_b("imm", op.imm as u64, false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("copyb").unwrap();
                    builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                    builder.i
                }
            ],

            // BPF opcode: `mov32 dst, imm` /// `dst = imm`.
            MOV32_IMM  => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_b("imm", op.imm as u64 & mask, false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("copyb").unwrap();
                    builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                    builder.i
                }
            ],

            // BPF opcode: `mov32 dst, src` /// `dst = src`.
            MOV32_REG => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("imm", mask, false);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", ireg_for_bpf_reg(op.src), false, false);
                    builder.op("and").unwrap();
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(pc + 1);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op("copyb").unwrap();
                    builder.j(TRANSPILE_ALIGN - 1, TRANSPILE_ALIGN - 1);
                    builder.i
                }
            ],

            // BPF opcode: `neg32 dst` /// `dst = -dst`.
            // BPF opcode: `neg64 dst` /// `dst = -dst`.
            NEG32 | NEG64 if !version.disable_neg() => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("imm", 0, false);
                    builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                    builder.op(if op.opc == NEG32 { "sub_w" } else { "sub" }).unwrap();
                    builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                    builder.i
                }
            ],

            // BPF opcode: `ja +off` /// `PC += off`.
            JA => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("imm", 0, false);
                    builder.src_b("imm", 0, false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op("flag").unwrap();
                    builder.j(TRANSPILE_ALIGN as i32 * (op.off + 1) as i32, TRANSPILE_ALIGN as i32 * (op.off + 1) as i32);
                    builder.i
                }
            ],


            // BPF opcode: `jeq dst, imm, +off` /// `PC += off if dst == imm`.
            // BPF opcode: `jne dst, imm, +off` /// `PC += off if dst != imm`.
            JNE_IMM | JEQ_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("imm", op.imm as u64, false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op("eq").unwrap();
                    builder.comment("jeq/jne imm");
                    if (op.opc & 0xf0) == BPF_JNE {
                        builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN * (op.off as i32 + 1));
                    } else {
                        builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    }
                    builder.i
                }
            ],
            // BPF opcode: `jeq dst, src, +off` /// `PC += off if dst == src`.
            // BPF opcode: `jne dst, src, +off` /// `PC += off if dst != src`.
            JNE_REG | JEQ_REG => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.src), false);
                    builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op("eq").unwrap();
                    if (op.opc & 0xf0) == BPF_JNE {
                        builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN * (op.off as i32 + 1));
                    } else {
                        builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    }
                    builder.i
                }
            ],

            // BPF opcode: `jgt dst, imm, +off` /// `PC += off if dst > imm`.
            // BPF opcode: `jsgt dst, imm, +off` /// `PC += off if dst > imm (signed)`.
            JSGT_IMM | JGT_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("imm", op.imm as u64, false);
                    builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op(if op.opc == JSGT_IMM {"lt"} else {"ltu"}).unwrap();
                    builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    builder.i
                }
            ],
            // BPF opcode: `jgt dst, src, +off` /// `PC += off if dst > src`.
            // BPF opcode: `jsgt dst, src, +off` /// `PC += off if dst > src (signed)`.
            JSGT_REG | JGT_REG => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.src), false);
                    builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op(if op.opc == JSGT_REG {"lt"} else {"ltu"}).unwrap();
                    builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    builder.i
                }
            ],
            // BPF opcode: `jlt dst, imm, +off` /// `PC += off if dst < imm`.
            // BPF opcode: `jslt dst, imm, +off` /// `PC += off if dst < imm (signed)`.
            JSLT_IMM | JLT_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("imm", op.imm as u64, false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op(if op.opc == JSLT_IMM {"lt"} else {"ltu"}).unwrap();
                    builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    builder.i
                }
            ],
            // BPF opcode: `jlt dst, src, +off` /// `PC += off if dst < src`.
            // BPF opcode: `jslt dst, src, +off` /// `PC += off if dst < src (signed)`.
            JSLT_REG | JLT_REG => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op(if op.opc == JSLT_REG {"lt"} else {"ltu"}).unwrap();
                    builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    builder.i
                }
            ],

            // BPF opcode: `jge dst, imm, +off` /// `PC += off if dst >= imm`.
            // BPF opcode: `jsge dst, imm, +off` /// `PC += off if dst >= imm (signed)`.
            JSGE_IMM | JGE_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("imm", op.imm as u64, false);
                    builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op(if op.opc == JSGE_IMM {"le"} else {"leu"}).unwrap();
                    builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    builder.i
                }
            ],
            // BPF opcode: `jge dst, src, +off` /// `PC += off if dst >= src`.
            // BPF opcode: `jsge dst, src, +off` /// `PC += off if dst >= src (signed)`.
            JSGE_REG | JGE_REG => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.src), false);
                    builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op(if op.opc == JSGE_REG {"le"} else {"leu"}).unwrap();
                    builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    builder.i
                }
            ],

            // BPF opcode: `jle dst, imm, +off` /// `PC += off if dst <= imm`.
            // BPF opcode: `jsle dst, imm, +off` /// `PC += off if dst <= imm (signed)`.
            JSLE_IMM | JLE_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("imm", op.imm as u64, false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op(if op.opc == JSLE_IMM {"le"} else {"leu"}).unwrap();
                    builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    builder.i
                }
            ],
            // BPF opcode: `jle dst, src, +off` /// `PC += off if dst <= src`.
            // BPF opcode: `jsle dst, src, +off` /// `PC += off if dst <= src (signed)`.
            JSLE_REG | JLE_REG => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                    builder.src_b("reg", reg_for_bpf_reg(op.src), false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op(if op.opc == JSLE_REG {"le"} else {"leu"}).unwrap();
                    builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    builder.i
                }
            ],
            
            // BPF opcode: `jset dst, imm, +off` /// `PC += off if dst & imm`.
            // BPF opcode: `jset dst, src, +off` /// `PC += off if dst & src`.
            JSET_REG | JSET_IMM => vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc);
                    if op.opc == JSET_REG {
                        builder.src_a("reg", reg_for_bpf_reg(op.src), false);
                    } else {
                        builder.src_a("imm", op.imm as u64, false);
                    }
                    builder.src_b("reg", reg_for_bpf_reg(op.dst), false);
                    builder.op("and").unwrap();
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(pc + 1);
                    builder.src_a("reg", SCRATCH_REG, false);
                    builder.src_b("imm", 0, false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op("eq").unwrap();
                    builder.j(TRANSPILE_ALIGN * (op.off as i32 + 1), TRANSPILE_ALIGN);
                    builder.i
                }
            ],




            // BPF opcode: `le dst` /// `dst = htole<imm>(dst), with imm in {16, 32, 64}`.
            // BPF opcode: `be dst` /// `dst = htobe<imm>(dst), with imm in {16, 32, 64}`.
            LE | BE => if {
                #[cfg(target_endian = "little")]
                {
                    op.opc == BE
                }
                #[cfg(not(target_endian = "little"))]
                {
                    op.opc == LE
                }
            } {
                // swapping bytes
                // we do it in 3 passes
                let steps_count = 3;
                let shifts = vec![32, 16, 8];
                let swap_masks = {
                    let mut masks = vec![];

                    for shift in shifts.as_slice() {
                        let mut mask = 0;
                        let submask = (1_u64 << shift) - 1;
                        for i in 0..64/(shift*2) {
                            mask |= submask << (shift * i * 2);
                        }
                        let bytemask = (1 << op.imm) - 1;
                        let to_swap_1 = mask & bytemask;
                        let to_swap_2 = !mask & bytemask;
                        masks.push((to_swap_1, to_swap_2));
                    }

                    masks
                };

                let mut insts = Vec::new();
                let mut pc = pc;
                for pass in 0..steps_count {
                    if shifts[pass]*2 <= op.imm {
                        insts.extend_from_slice(
                            vec![
                                {
                                    let mut builder = ZiskInstBuilder::new(pc);
                                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                                    builder.src_b("imm", swap_masks[pass].0, false);
                                    builder.op("and").unwrap();
                                    builder.store("reg", SCRATCH_REG as i64, false, false);
                                    builder.j(1, 1);
                                    builder.i
                                },
                                {
                                    let mut builder = ZiskInstBuilder::new(pc + 1);
                                    builder.src_a("reg", reg_for_bpf_reg(op.dst), false);
                                    builder.src_b("imm", swap_masks[pass].1, false);
                                    builder.op("and").unwrap();
                                    builder.store("reg", SCRATCH_REG2 as i64, false, false);
                                    builder.j(1, 1);
                                    builder.i
                                },
                                {
                                    let mut builder = ZiskInstBuilder::new(pc + 2);
                                    builder.src_a("reg", SCRATCH_REG, false);
                                    builder.src_b("imm", shifts[pass] as u64, false);
                                    builder.op("sll").unwrap();
                                    builder.store("reg", SCRATCH_REG as i64, false, false);
                                    builder.j(1, 1);
                                    builder.i
                                },
                                {
                                    let mut builder = ZiskInstBuilder::new(pc + 3);
                                    builder.src_a("reg", SCRATCH_REG2, false);
                                    builder.src_b("imm", shifts[pass] as u64, false);
                                     builder.op("srl").unwrap();
                                    builder.store("reg", SCRATCH_REG2 as i64, false, false);
                                    builder.j(1, 1);
                                    builder.i
                                },
                                {
                                    let mut builder = ZiskInstBuilder::new(pc + 4);
                                    builder.src_a("reg", SCRATCH_REG, false);
                                    builder.src_b("reg", SCRATCH_REG2, false);
                                    builder.op("or").unwrap();
                                    builder.store("reg", ireg_for_bpf_reg(op.dst), false, false);
                                    builder.j(1, 1);
                                    builder.i
                                }
                            ].as_slice());
                            pc += 5;
                    }
                }

                insts.last_mut().map(|x| {
                    let rem = x.paddr % TRANSPILE_ALIGN as u64;
                    x.jmp_offset1 = (TRANSPILE_ALIGN as u64 - rem) as i64;
                    x.jmp_offset2 = x.jmp_offset1;
                });

                insts
            } else {
                vec![{
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("imm", 0, false);
                    builder.src_b("imm", 0, false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op("flag").unwrap();
                    builder.j(TRANSPILE_ALIGN as i32, TRANSPILE_ALIGN as i32);
                    builder.i
                }]
            },


            // BPF opcode: `exit` /// `return r0`. /// Valid only until SBPFv3
            EXIT if !version.static_syscalls() => Self::gen_pop_frame(pc),

            // BPF opcode: `return` /// `return r0`. /// Valid only since SBPFv3
            RETURN => Self::gen_pop_frame(pc),

            // BPF opcode: `call imm` /// syscall function call to syscall with key `imm`.
            CALL_IMM | SYSCALL => Self::gen_push_frame(version, pc, pc + TRANSPILE_ALIGN as u64, config,
                |pc| {
                    let mut builder = ZiskInstBuilder::new(pc);
                    let key = if version.static_syscalls() {
                        (op.ptr as i64).saturating_add(op.imm).saturating_add(1) as u32
                    } else {
                        op.imm as u32
                    };

                    let pc = call_map.get(&key);
                    if pc.is_none() {
                        for (key, (name, _)) in LoadEnv::new().unwrap().loader.get_function_registry().iter() {
                            if key == op.imm as u32 {
                                panic!("not found syscall {0} with key {key} from the default env", unsafe {str::from_utf8_unchecked(name)});
                            }

                        }
                        panic!("not found for imm {0}", op.imm as u32);
                    }
                    let pc = *pc.unwrap();
                    builder.src_a("imm", pc, false);
                    builder.src_b("imm", pc, false);
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.op("copyb").unwrap();
                    builder.set_pc();
                    builder.i
                }),

            // BPF opcode: tail call.
            CALL_REG => {
                let target_reg = if version.callx_uses_src_reg() {
                    op.src
                } else {
                    op.imm as u8
                };
                vec![{
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("reg", reg_for_bpf_reg(target_reg), false);
                    builder.src_b("reg", reg_for_bpf_reg(target_reg), false);
                    builder.op("copyb").unwrap();
                    builder.store("reg", TRANSLATE_REG as i64, false, false);
                    builder.comment("call reg");
                    builder.j(1, 1);
                    builder.i
                }].into_iter().chain(
                    Self::gen_push_frame(version, pc + 1, pc + TRANSPILE_ALIGN as u64, config,
                        |pc| {
                            let mut builder = ZiskInstBuilder::new(pc);
                            builder.src_a("imm", translate_pc_routine, false);
                            builder.src_b("imm", translate_pc_routine, false);
                            builder.op("copyb").unwrap();
                            builder.store("reg", SCRATCH_REG as i64, false, false);
                            builder.comment("call reg jump");
                            builder.set_pc();
                            builder.i
                        }).into_iter())
                .collect()
            },

            _ => vec![]
        }
    }

    fn wrap_sync_sys_regs(pc: u64, solana_pc: u64, insts: Vec<ZiskInst>, sync_cu: bool) -> Vec<ZiskInst>  {
        let mut result = vec![
            // set pc for bpf
            {
                let mut builder = ZiskInstBuilder::new(pc);
                builder.src_a("imm", solana_pc, false);
                builder.src_b("imm", solana_pc, false);
                builder.op("copyb").unwrap();
                builder.store("reg", ireg_for_bpf_reg(11), false, false);
                builder.j(1, 1);
                builder.comment("sync pc");
                builder.i
            },
            // HERE We have totally synced registers with solana
        ];

        if sync_cu {
            result.push(
                // decrease cu
                {
                    let mut builder = ZiskInstBuilder::new(pc + 1);
                    builder.src_a("reg", CU_METER_REG, false);
                    builder.src_b("imm", 1_u64, false);
                    builder.store("reg", CU_METER_REG as i64, false, false);
                    builder.op("sub").unwrap();
                    builder.comment("sync cu");
                    builder.j(1, 1);
                    builder.i
                },
            );
        }

        result.extend(insts.into_iter().enumerate().map(|(i, x)| {
            let mut inst = x;
            assert!(inst.paddr == pc + i as u64, "inst.paddr={}, pc={pc}, i={i}", inst.paddr);
            let delta = if sync_cu {2} else {1};
            inst.paddr += delta as u64;
            if !inst.set_pc {
                if inst.jmp_offset1.abs() + i as i64 >= TRANSPILE_ALIGN.into() {
                    inst.jmp_offset1 -= delta;
                }
                if inst.jmp_offset2.abs() + i as i64 >= TRANSPILE_ALIGN.into() {
                    inst.jmp_offset2 -= delta;
                }
            }

            inst
        }));

        result
    }

    // 6 registers
    fn scratch_registers() -> Vec<u8> {
        let mut res = Vec::<u8>::new();
        for reg in 0..ebpf::SCRATCH_REGS as u8 {
            res.push(reg + ebpf::FIRST_SCRATCH_REG as u8);
        }
        res.push(ebpf::FRAME_PTR_REG as u8);
        res.push(11);
        res
    }

    // generates 10 instructions
    fn gen_push_frame(version: &SBPFVersion, pc: u64, ret_pc: u64, solana_conf: &Config, gen_jump: impl Fn(u64) -> ZiskInst) -> Vec<ZiskInst> {
        // 4 bpf registers + pc
        // 5 * u64 = 40
        let registers = Self::scratch_registers();
        let frame_sz = registers.len() as u64;
        registers.into_iter().enumerate().map(
            |(i, reg)| {
                let mut builder = ZiskInstBuilder::new(pc + i as u64);
                builder.src_a("reg", FRAME_REGS_PTR, false);
                builder.src_b("reg", reg_for_bpf_reg(reg), false);
                builder.op("copyb").unwrap();
                builder.store("ind", i as i64 * 8, false, false);
                builder.comment("frame save registers");
                builder.ind_width(8);
                builder.j(1, 1);
                builder.i
            })
        .chain(vec![
        {
            let mut builder = ZiskInstBuilder::new(pc + frame_sz);
            builder.src_a("reg", FRAME_REGS_PTR, false);
            builder.src_b("imm", ret_pc, false);
            builder.op("copyb").unwrap();
            builder.store("ind", frame_sz as i64 * 8, false, false);
            builder.comment("write ret_pc");
            builder.ind_width(8);
            builder.j(1, 1);
            builder.i
        },
        {
            let mut builder = ZiskInstBuilder::new(pc + frame_sz + 1);
            builder.src_a("reg", FRAME_REGS_PTR, false);
            builder.src_b("imm", (frame_sz + 1)*8, false);
            builder.op("add").unwrap();
            builder.comment("upd zisk frame_regs_ptr");
            builder.store("reg", FRAME_REGS_PTR as i64, false, false);
            builder.j(1, 1);
            builder.i
        }])
        .chain(if ! version.dynamic_stack_frames() {
            vec![
                {
                    let mut builder = ZiskInstBuilder::new(pc + frame_sz + 2);
                    builder.src_a("reg", reg_for_bpf_reg(ebpf::FRAME_PTR_REG as u8), false);

                    let delta = solana_conf.stack_frame_size * if solana_conf.enable_stack_frame_gaps { 2 } else { 1 };
                    builder.src_b("imm", delta as u64, false);
                    builder.op("add").unwrap();
                    builder.store("reg", ireg_for_bpf_reg(ebpf::FRAME_PTR_REG as u8), false, false);
                    builder.comment("upd bpf frame_ptr_reg");
                    builder.j(1, 1);
                    builder.i
                }
            ]
        } else { vec![] }.into_iter())
        .chain(vec![gen_jump({
            if version.dynamic_stack_frames() {
                pc + frame_sz + 2
            } else {
                pc + frame_sz + 3
            }
        })].into_iter())
        .collect()
    }

    fn gen_pop_frame(pc: u64) -> Vec<ZiskInst> {
        let scratch_registers = Self::scratch_registers();
        let frame_sz = scratch_registers.len() as u64;
        vec![{
            let mut builder = ZiskInstBuilder::new(pc);
            builder.src_a("reg", FRAME_REGS_PTR, false);
            builder.src_b("imm", (frame_sz + 1)*8, false);
            builder.op("sub").unwrap();
            builder.store("reg", FRAME_REGS_PTR as i64, false, false);
            builder.j(1, 1);
            builder.comment("upd zisk frame regs");
            builder.i
        }].into_iter().chain(
        scratch_registers.into_iter().enumerate().map(|(i, reg)| {
            let mut builder = ZiskInstBuilder::new(pc + 1 + i as u64);
            builder.src_a("reg", FRAME_REGS_PTR, false);
            builder.src_b("ind", i as u64 * 8, false);
            builder.op("copyb").unwrap();
            builder.store("reg", ireg_for_bpf_reg(reg), false, false);
            builder.ind_width(8);
            builder.j(1, 1);
            builder.comment("restore registers");
            builder.i
        }))
        .chain(vec![
            {
                let mut builder = ZiskInstBuilder::new(pc + 1 + frame_sz);
                builder.src_a("reg", FRAME_REGS_PTR, false);
                builder.src_b("ind", frame_sz * 8, false);
                builder.op("copyb").unwrap();
                builder.store("reg", SCRATCH_REG as i64, false, false);
                builder.comment("restore pc");
                builder.set_pc();
                builder.ind_width(8);
                builder.i
            }
        ].into_iter()).collect()
    }

    pub fn elfs_hash_from_path(path: PathBuf) -> String {
        let mut meta_path = path.clone();
        meta_path.push("metadata");
        let meta_content = std::fs::read_to_string(meta_path).unwrap();
        let meta = serde_json::from_str::<AccountInventory>(meta_content.as_str()).unwrap();
        let mut hasher = blake3::Hasher::new();
        for acc in meta.accounts.as_slice() {
            if acc.executable {
                hasher.update(&acc.key.to_bytes());
                let mut file = path.clone();
                file.push(acc.file.clone());
                hasher.update(&std::fs::read(file).unwrap());
            }
        }

        hasher.finalize().to_string()
    }

    pub fn load_from_path(path: PathBuf) -> (Self, Vec<(Pubkey, Account)>) {
        let mut meta_path = path.clone();
        meta_path.push("metadata");
        let meta = serde_json::from_str::<AccountInventory>(std::fs::read_to_string(meta_path).unwrap().as_str()).unwrap();
        let mut accounts = vec![];
        let mut rom: Option<ZiskRom> = Option::None;
        let syscalls_stub = load_elf_from_path(LoadEnv::new_with_debugging().unwrap(), meta.syscalls_stubs.clone().into()).expect(format!("loading from {:?}", meta.syscalls_stubs).as_str());
        for acc in meta.accounts.as_slice() {
            let data = {
                let mut file = path.clone();
                file.push(acc.file.clone());
                std::fs::read(file).expect(format!("failed to {0}", acc.file).as_str())
            };
            if acc.key == meta.main_program {
                rom = Some(Self::new(
                    meta.main_program,
                    load_elf(LoadEnv::new().unwrap(), data.as_slice()).expect(format!("loading from {:?}", path.as_path()).as_str()),
                    &syscalls_stub));
            }
            accounts.push((acc.key, Account {
                owner: acc.owner,
                lamports: acc.lamports,
                executable: acc.executable,
                rent_epoch: acc.rent_epoch,
                data 
            }));
        }

        (rom.unwrap(), accounts)
    }

    pub fn sol_pc(&self, zisk_pc: u64) -> Option<u64> {
        if zisk_pc >= ROM_ADDR {
            let align = TRANSPILE_ALIGN as u64;
            let line = (zisk_pc - ROM_ADDR) / align;
            let index = (zisk_pc - ROM_ADDR) % align;

            // after pc sync
            if index == 1 {
                Some(line)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn ro_section_iter<'a>(data: &'a [u8]) -> impl 'a + Iterator<Item = (/* number */ usize, /* is_last */ bool, /* val */ u64)> {
        assert!(data.len() % 8 == 0);
        let size = data.len() / 8;
        data.chunks(size_of::<u64>()).map(|x| {
            // as i know, zisk is big-endian
            u64::from_le_bytes(x.try_into().unwrap()) 
        }).into_iter().enumerate().map(move |(i, val)| (i, i + 1 == size, val))
    }
 
    pub fn new(key: Pubkey, program: ProcessedElf, bios: &ProcessedElf) -> Self {
        assert!(program.config.enable_stack_frame_gaps == bios.config.enable_stack_frame_gaps);
        assert!(program.config.stack_frame_size == bios.config.stack_frame_size);
        let mut call_map = BTreeMap::<u32, u64>::new();
        assert!(ROM_ENTRY % TRANSPILE_ALIGN as u64 == 0);
        assert!(ROM_ADDR % TRANSPILE_ALIGN as u64 == 0);

        let base_ptr = {
            let last_inst = ROM_ENTRY + (program.ro_section_bytes.len() as u64 /8);
            ((last_inst - 1) / TRANSPILE_ALIGN as u64 + 1) * TRANSPILE_ALIGN as u64
        };

        let mut system_instructions = Self::ro_section_iter(&program.ro_section_bytes)
            .map(|(i, is_last, val)| {
                let ptr = program.ro_section_vmaddr + i as u64 * 8;
                assert!(ptr%8 == 0);
                let pc = ROM_ENTRY + i as u64;
                let mut builder = ZiskInstBuilder::new(pc);
                builder.src_a("imm", ptr, false);
                builder.src_b("imm", val, false);
                builder.op("copyb").unwrap();
                builder.ind_width(8);
                builder.store("mem", ptr as i64, false, false);
                builder.comment("rom init");
                builder.j(1, 1);
                if is_last {
                    let off = (base_ptr - pc).try_into().unwrap();
                    builder.j(off, off);
                }
                builder.i
            }).collect::<Vec<_>>().chunks(TRANSPILE_ALIGN as usize).map(|x| x.to_vec()).collect::<Vec<_>>();

        // abort syscall
        call_map.insert(3069975057, ROM_EXIT);

        let sys_translate_pc_routine = base_ptr + 3 * TRANSPILE_ALIGN as u64;
        let user_translate_pc_routine = base_ptr + 4 * TRANSPILE_ALIGN as u64;
        let sys_pc = base_ptr + 5 * TRANSPILE_ALIGN as u64;
        {
            let env = LoadEnv::new().unwrap();
            for (key, (symbol, pc)) in bios.function_registry.iter() {
                let mut key = key as u32;
                for (skey, (ssymbol, _)) in env.loader.get_function_registry().iter() {
                    if symbol == ssymbol {
                        key = skey;
                    }
                }
                //println!("symbol \"{0}\" with key={key} in bios registry ", unsafe {str::from_utf8_unchecked(symbol)});
                call_map.insert(key, sys_pc + pc as u64 * TRANSPILE_ALIGN as u64);
            }
        }

        // no montamos los datos de syscalls así que sería mejor que no uses las variables globales en "bios"
        system_instructions.extend(
            vec![
            vec![{
                let mut builder = ZiskInstBuilder::new(base_ptr);
                builder.src_a("imm", FRAME_REGS_START, false);
                builder.src_b("imm", FRAME_REGS_START, false);
                builder.op("copyb").unwrap();
                builder.store("reg", FRAME_REGS_PTR as i64, false, false);
                builder.j(1, 1);
                builder.comment("reg init");
                builder.i
            },
            {
                let mut builder = ZiskInstBuilder::new(base_ptr + 1);
                builder.src_a("imm", ebpf::MM_INPUT_START, false);
                builder.src_b("imm", ebpf::MM_INPUT_START, false);
                builder.op("copyb").unwrap();
                builder.store("reg", ireg_for_bpf_reg(1), false, false);
                builder.j(1, 1);
                builder.comment("reg init");
                builder.i
            },
            {
                let mut builder = ZiskInstBuilder::new(base_ptr + 2);

                let stack_size = program.config.stack_size() as usize;
                let delta = if !program.sbpf_version.dynamic_stack_frames() {
                    program.config.stack_frame_size as u64 * if program.config.enable_stack_frame_gaps { 2 } else { 1 }
                } else { 0 };

                let frame_ptr =
                    ebpf::MM_STACK_START.saturating_add(if program.sbpf_version.dynamic_stack_frames() {
                        // the stack is fully descending, frames start as empty and change size anytime r11 is modified
                        stack_size
                    } else {
                        // within a frame the stack grows down, but frames are ascending
                        program.config.stack_frame_size
                    } as u64) - delta;
                builder.src_a("imm", frame_ptr, false);
                builder.src_b("imm", frame_ptr, false);
                builder.op("copyb").unwrap();
                builder.store("reg", ireg_for_bpf_reg(ebpf::FRAME_PTR_REG as u8), false, false);
                builder.j(TRANSPILE_ALIGN - 1, TRANSPILE_ALIGN - 1);
                builder.comment("reg init");
                builder.i
            }],
            Self::gen_push_frame(
                &program.sbpf_version,
                base_ptr + TRANSPILE_ALIGN as u64,
                base_ptr + 2 * TRANSPILE_ALIGN as u64,
                &program.config,
                |pc| {
                    let mut builder = ZiskInstBuilder::new(pc);
                    builder.src_a("imm", 0, false);
                    const ENTRYPOINT_KEY: u32 = 0x71E3CF81;
                    let entry_pc = program.function_registry.lookup_by_key(ENTRYPOINT_KEY).unwrap().1 as u64;
                    let entry_pc = ROM_ADDR + entry_pc * TRANSPILE_ALIGN as u64;
                    builder.src_b("imm", entry_pc, false);
                    builder.op("copyb").unwrap();
                    builder.comment("jumping to the rom entry");
                    builder.set_pc();
                    builder.i
                }),
            vec![{
                let mut builder = ZiskInstBuilder::new(base_ptr + 2*TRANSPILE_ALIGN as u64);
                builder.src_a("imm", 0, false);
                builder.src_b("imm", ROM_EXIT, false);
                builder.comment("rom exit");
                builder.op("copyb").unwrap();
                builder.set_pc();
                builder.i
            }],
            vec![
                {
                    let mut builder = ZiskInstBuilder::new(sys_translate_pc_routine);
                    builder.src_a("reg", TRANSLATE_REG, false);
                    builder.src_b("imm", bios.text_vmaddr, false);
                    builder.op("sub").unwrap();
                    builder.store("reg", TRANSLATE_REG as i64, false, false);
                    builder.comment("user translate pc");
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(sys_translate_pc_routine + 1);
                    builder.src_a("reg", TRANSLATE_REG, false);
                    builder.src_a("imm", ebpf::INSN_SIZE as u64, false);
                    builder.op("divu").unwrap();
                    builder.store("reg", TRANSLATE_REG as i64, false, false);
                    builder.comment("user translate pc");
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(sys_translate_pc_routine + 2);
                    builder.src_a("imm", TRANSPILE_ALIGN as u64, false);
                    builder.src_b("reg", TRANSLATE_REG, false);
                    builder.op("mulu").unwrap();
                    builder.store("reg", TRANSLATE_REG as i64, false, false);
                    builder.comment("sys translate pc");
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(sys_translate_pc_routine + 3);
                    builder.src_a("imm", sys_pc, false);
                    builder.src_b("reg", TRANSLATE_REG, false);
                    builder.op("add").unwrap();
                    builder.store("reg", TRANSLATE_REG as i64, false, false);
                    builder.comment("sys translate pc");
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(sys_translate_pc_routine + 4);
                    builder.src_a("reg", TRANSLATE_REG, false);
                    builder.src_b("reg", TRANSLATE_REG, false);
                    builder.op("copyb").unwrap();
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.set_pc();
                    builder.comment("sys translate pc");
                    builder.i
                }
            ],
            vec![
                {
                    let mut builder = ZiskInstBuilder::new(user_translate_pc_routine);
                    builder.src_a("reg", TRANSLATE_REG, false);
                    builder.src_b("imm", program.text_vmaddr, false);
                    builder.op("sub").unwrap();
                    builder.store("reg", TRANSLATE_REG as i64, false, false);
                    builder.comment("user translate pc");
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(user_translate_pc_routine + 1);
                    builder.src_a("reg", TRANSLATE_REG, false);
                    builder.src_b("imm", ebpf::INSN_SIZE as u64, false);
                    builder.op("divu").unwrap();
                    builder.store("reg", TRANSLATE_REG as i64, false, false);
                    builder.comment("user translate pc");
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(user_translate_pc_routine + 2);
                    builder.src_a("imm", TRANSPILE_ALIGN as u64, false);
                    builder.src_b("reg", TRANSLATE_REG, false);
                    builder.op("mulu").unwrap();
                    builder.store("reg", TRANSLATE_REG as i64, false, false);
                    builder.comment("user translate pc");
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(user_translate_pc_routine + 3);
                    builder.src_a("imm", ROM_ADDR, false);
                    builder.src_b("reg", TRANSLATE_REG, false);
                    builder.op("add").unwrap();
                    builder.store("reg", TRANSLATE_REG as i64, false, false);
                    builder.comment("user translate pc");
                    builder.j(1, 1);
                    builder.i
                },
                {
                    let mut builder = ZiskInstBuilder::new(user_translate_pc_routine + 4);
                    builder.src_a("reg", TRANSLATE_REG, false);
                    builder.src_b("reg", TRANSLATE_REG, false);
                    builder.op("copyb").unwrap();
                    builder.store("reg", SCRATCH_REG as i64, false, false);
                    builder.comment("user translate pc");
                    builder.set_pc();
                    builder.i
                }
            ],
        ]);

        assert_eq!(bios.sbpf_version.dynamic_stack_frames(), program.sbpf_version.dynamic_stack_frames());

        {
            let mut index = 0;
            for op in bios.all_lines.as_slice() {
                if op.ptr != index {
                    system_instructions.push(vec![{
                        let mut builder = ZiskInstBuilder::new(sys_pc + index as u64 * TRANSPILE_ALIGN as u64);
                        builder.src_a("imm", 0, false);
                        builder.src_b("imm", 0, false);
                        builder.op("copyb").unwrap();
                        builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                        builder.store("reg", SCRATCH_REG as i64, false, false);
                        builder.comment("noop stub");
                        builder.i
                    }]);
                    index += 1;
                }
                let pc = sys_pc + op.ptr as u64 * TRANSPILE_ALIGN as u64;
                let insts = Self::transpile_op(&op, pc, sys_translate_pc_routine, &bios.sbpf_version, &bios.config, &call_map);
                system_instructions.push(Self::wrap_sync_sys_regs(pc, op.ptr as u64, insts, false));
                assert!(op.ptr == index);
                index += 1;
            }
        }

        for (key, (_symbol, pc)) in program.function_registry.iter() {
            call_map.insert(key, ROM_ADDR + pc as u64 * TRANSPILE_ALIGN as u64);
        }

        assert!(program.all_lines[0].ptr == 0);
        let transpiled_instructions = {
            let mut transpiled_instructions = Vec::<_>::new();
            let mut index = 0;
            for op in program.all_lines.as_slice().iter() {
                if op.ptr != index {
                    transpiled_instructions.push(vec![{
                        let mut builder = ZiskInstBuilder::new(ROM_ADDR + index as u64 * TRANSPILE_ALIGN as u64);
                        builder.src_a("imm", 0, false);
                        builder.src_b("imm", 0, false);
                        builder.op("copyb").unwrap();
                        builder.j(TRANSPILE_ALIGN, TRANSPILE_ALIGN);
                        builder.store("reg", SCRATCH_REG as i64, false, false);
                        builder.comment("noop stub");
                        builder.i
                    }]);
                    index += 1;
                }
                let pc = ROM_ADDR + op.ptr as u64 * TRANSPILE_ALIGN as u64;
                let insts = Self::transpile_op(op, pc, user_translate_pc_routine, &program.sbpf_version, &program.config, &call_map);
                transpiled_instructions.push(Self::wrap_sync_sys_regs(pc, op.ptr as u64, insts, true));
                assert!(op.ptr == index);
                index += 1;
            }

            transpiled_instructions
        };

        for (line, insts) in system_instructions.as_slice().iter().enumerate() {
            for (cmd, inst) in insts.as_slice().iter().enumerate() {
                assert!(cmd < TRANSPILE_ALIGN as usize);
                assert!(ROM_ENTRY + line as u64 * TRANSPILE_ALIGN as u64 + cmd as u64 == inst.paddr,
                    "failed paddr verification for {line} {cmd}, difference {}/{}", ROM_ENTRY + line as u64 * TRANSPILE_ALIGN as u64 + cmd as u64, inst.paddr);
                assert!(inst.set_pc || (inst.jmp_offset1 != 0 && inst.jmp_offset2 != 0));
            }
        }

        for (line, insts) in transpiled_instructions.as_slice().iter().enumerate() {
            for (cmd, inst) in insts.as_slice().iter().enumerate() {
                assert!(cmd < TRANSPILE_ALIGN as usize,
                   "failed program paddr verification for {line} {cmd} transplied inst was {:?} result was {:?}", program.all_lines[line], insts);
                assert!(ROM_ADDR + line as u64 * TRANSPILE_ALIGN as u64 + cmd as u64 == inst.paddr,
                    "failed program paddr verification for {line} {cmd} transplied inst was {:?} result was {:?}", program.all_lines[line], insts);
                assert!(inst.set_pc || (inst.jmp_offset1 != 0 && inst.jmp_offset2 != 0));
            }
        }

        let end_insts = vec![{
            let mut builder = ZiskInstBuilder::new(ROM_EXIT);
            builder.src_a("imm", 0, false);
            builder.src_b("imm", 0, false);
            builder.op("flag").unwrap();
            builder.store("reg", SCRATCH_REG as i64, false, false);
            builder.end();
            builder.i
        }];

        Self {
            key,
            program,
            transpiled_instructions,
            system_instructions,
            end_insts
        }
    }

    ///// Gets the ROM instruction corresponding to the provided pc address.
    ///// Depending on the range and allignment of the address, the function searches for it in the
    ///// corresponding vector.
    //#[inline(always)]
    pub fn get_instruction(&self, pc: u64) -> &ZiskInst {
        //println!("zisk pc {pc}");
        // If the address is a program address...
        let end_addr = self.end_insts[0].paddr;
        if {
            let end_limit_addr = end_addr + TRANSPILE_ALIGN as u64;
            pc >= end_addr && pc < end_limit_addr
        } {
            let cmd = pc - end_addr;
            &self.end_insts[cmd as usize]
        } else if pc >= ROM_ADDR {
            let align = TRANSPILE_ALIGN as u64;
            let line = (pc - ROM_ADDR) / align;
            let index = (pc - ROM_ADDR) % align;

            &self.transpiled_instructions[line as usize][index as usize]
        } else if pc >= ROM_ENTRY {
            let align = TRANSPILE_ALIGN as u64;
            let line = (pc - ROM_ENTRY) / align;
            let index = (pc - ROM_ENTRY) % align;

            &self.system_instructions[line as usize][index as usize]
        } else {
            panic!("ZiskRom::get_instruction() pc={pc} is out of range");
        }
    }

    pub fn pc_iter<'a>(&'a self) -> impl 'a + Iterator<Item = u64> {
        self.system_instructions.as_slice().iter()
            .chain(std::iter::once(&self.end_insts))
            .chain(self.transpiled_instructions.as_slice().iter())
            .flat_map(|items| items.as_slice().iter().map(|inst| inst.paddr))
    }

    pub fn build_constant_trace<F: PrimeField64>(&self) -> Vec<MainTraceRow<F>> {
        let mut inss = 0;
        for ins in self.transpiled_instructions.as_slice().iter().chain(self.system_instructions.as_slice()) {
            inss += ins.len() 
        }
        inss += self.system_instructions.len();

        let mut result: Vec<MainTraceRow<F>> = Vec::with_capacity(inss);
        #[allow(clippy::uninit_vec)]
        unsafe {
            result.set_len(inss)
        };

        let mut ix = 0;

        for line in self.system_instructions.as_slice().iter().chain(self.transpiled_instructions.as_slice()) {
            for insn in line {
                insn.write_constant_trace(result.get_mut(ix).unwrap());
                ix += 1;
            }
        }

        result
    }
}
