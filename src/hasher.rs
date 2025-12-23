use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    circuit::Layouter,
    circuit::Value,
    dev::MockProver,
    plonk::{self, Advice, ConstraintSystem, Circuit, Column, Instance, Expression, Selector},
};
use std::marker::PhantomData;
use halo2_proofs::circuit::Cell;
use halo2_ecc::fields::PrimeField;

use halo2_gadgets::sha256::{table16::*, Sha256Instructions, BLOCK_SIZE};
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    halo2curves::bn256::Fr,
    plonk::{
        Any, Constraints, Error, Fixed, TableColumn,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::convert::TryInto;
//type BlockState = <Table16Chip as Sha256Instructions<F>>::State;

/// u32 size for SHA256 digit
pub const DIGEST_SIZE: usize = 8;

/// the definition for a sha256 table
pub trait SHA256Table {
    /// the cols has layout [s_enable, input_bytes, input_len, hashes, effect]
    fn cols(&self) -> [Column<Any>; 5];

    /// s_enable col with cell *EQUAL TO 1* mark the row is an effect entry for
    /// *ANY* 512-bit block of SHA256
    fn s_enable(&self) -> Column<Fixed> {
        self.cols()[0]
            .try_into()
            .expect("must provide cols as expected layout")
    }
    /// input_rlc show the RLC for input bytes, the first byte is multiplied with R^(n-1)
    /// in which n is the length of bytes and R is random
    fn input_rlc(&self) -> Column<Advice> {
        self.cols()[1]
            .try_into()
            .expect("must provide cols as expected layout")
    }
    /// input_len show the accumulated length for input bytes
    fn input_len(&self) -> Column<Advice> {
        self.cols()[2]
            .try_into()
            .expect("must provide cols as expected layout")
    }
    /// hashes_rlc show the RLC for the 32-bytes digest of input bytes, the first byte
    /// is multiplied with R^31
    fn hashes_rlc(&self) -> Column<Advice> {
        self.cols()[3]
            .try_into()
            .expect("must provide cols as expected layout")
    }
    /// is_effect col is a phase 0 col, when the cell is equal to 1 indicate this 512-bit
    /// block is the final one for current input bytes, the input_len in this row would
    /// show the length *WITHOUT* padding of input bytes
    fn is_effect(&self) -> Column<Advice> {
        self.cols()[4]
            .try_into()
            .expect("must provide cols as expected layout")
    }
}

/// CircuitConfig is the configure for SHA256 circuit
#[derive(Clone, Debug)]
pub struct CircuitConfig<F: PrimeField> {
    table16: Table16Config,
    byte_range: TableColumn,
    c_data: Column<Fixed>,

    copied_data: Column<Advice>,
    trans_byte: Column<Advice>,
    bytes_rlc: Column<Advice>, /* phase 2 col obtained from SHA256 table, used for saving the
                                * rlc bytes from input */
    helper: Column<Advice>, /* phase 2 col used to save series of data, like the final input rlc
                             * cell, the padding bit count, etc */

    s_final_block: Column<Advice>, /* indicate it is the last block, it can be 0/1 in input
                                    * region and */
    // digest region is set the same as corresponding input region
    s_padding: Column<Advice>,    // indicate cur bytes is padding
    byte_counter: Column<Advice>, // counting for the input bytes

    s_output: Column<Fixed>, // indicate the row is used for output to sha256 table

    final_output: Column<Advice>, 

    s_begin: Selector,        // indicate as the first line in region
    s_final: Selector,        // indicate the last byte
    s_enable: Selector,       // indicate the main rows
    s_common_bytes: Selector, // mark the s_enable region except for the last 8 bytes
    s_padding_size: Selector, // mark the last 8 bytes for padding size
    s_assigned_u16: Selector, // indicate copied_data cell is a assigned u16 word
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
struct BlockInheritments<F: PrimeField> {
    s_final: AssignedBits<F, 1>,
    s_padding: AssignedBits<F, 1>,
    byte_counter: AssignedCell<F, F>,
    bytes_rlc: AssignedCell<F, F>,
}

impl<F: PrimeField> CircuitConfig<F> {
    fn setup_gates(&self, meta: &mut ConstraintSystem<F>, rnd: Expression<F>) {
        let one = Expression::Constant(F::ONE);
        meta.create_gate("halves to rlc_byte", |meta| {
            let s_u16 = meta.query_selector(self.s_assigned_u16);
            let u16 = meta.query_advice(self.copied_data, Rotation::cur());
            let byte = meta.query_advice(self.trans_byte, Rotation::cur());
            let byte_next = meta.query_advice(self.trans_byte, Rotation::next());
            let rlc_byte_prev = meta.query_advice(self.bytes_rlc, Rotation::prev());
            let rlc_byte = meta.query_advice(self.bytes_rlc, Rotation::cur());

            let s_enable = meta.query_selector(self.s_enable);
            let s_padding = meta.query_advice(self.s_padding, Rotation::cur());
            let s_not_padding = one.clone() - s_padding.clone();

            // constraint u16 in table16 with byte
            let byte_from_u16 =
                s_u16 * (u16 - (byte.clone() * Expression::Constant(F::from(256u64)) + byte_next));

            let byte_rlc = rlc_byte
                - s_not_padding * (rlc_byte_prev.clone() * rnd + byte)
                - s_padding * rlc_byte_prev;

            vec![byte_from_u16, s_enable * byte_rlc]
        });

        meta.create_gate("sha256 block padding", |meta| {
            let s_padding = meta.query_advice(self.s_padding, Rotation::cur());
            let s_padding_prev = meta.query_advice(self.s_padding, Rotation::prev());

            let byte = meta.query_advice(self.trans_byte, Rotation::cur());
            let byte_counter = meta.query_advice(self.byte_counter, Rotation::cur());
            let byte_counter_prev = meta.query_advice(self.byte_counter, Rotation::prev());

            let is_final = meta.query_advice(self.s_final_block, Rotation::cur());

            let padding_is_bool = s_padding.clone() * (one.clone() - s_padding.clone());
            let s_not_padding = one.clone() - s_padding.clone();

            let byte_counter_continue = s_not_padding
                * (byte_counter.clone() - (byte_counter_prev.clone() + one.clone()))
                + s_padding.clone() * (byte_counter - byte_counter_prev);

            let padding_change = s_padding - s_padding_prev.clone();

            // if prev padding is 1, the following padding would always 1 (no change)
            let padding_continue = s_padding_prev.clone() * padding_change.clone();

            // the byte on first padding is 128 (first bit is 1)
            let padding_byte_on_change =
                padding_change.clone() * (byte.clone() - Expression::Constant(F::from(128u64)));

            // constraint the padding byte, notice it in fact constraint the first byte of the final
            // 64-bit integer is 0, but it is ok (we have no so large bytes for 48-bit
            // integer)
            let padding_byte_is_zero = s_padding_prev * is_final.clone() * byte;

            let padding_change_on_size =
                meta.query_selector(self.s_padding_size) * is_final * padding_change;

            Constraints::with_selector(
                meta.query_selector(self.s_enable),
                vec![padding_is_bool, padding_continue, byte_counter_continue],
            )
            .into_iter()
            .chain(Constraints::with_selector(
                meta.query_selector(self.s_common_bytes),
                vec![padding_byte_is_zero, padding_byte_on_change],
            ))
            .chain(vec![padding_change_on_size.into()])
        });

        meta.create_gate("sha256 block final", |meta| {
            let is_final = meta.query_advice(self.s_final_block, Rotation::cur());
            // final is decided by the begin row
            let final_continue =
                is_final.clone() - meta.query_advice(self.s_final_block, Rotation::prev());
            let final_is_bool = is_final.clone() * (one.clone() - is_final.clone());

            let byte = meta.query_advice(self.trans_byte, Rotation::cur());
            let padding_size = meta.query_advice(self.helper, Rotation::cur());
            let padding_size_prev = meta.query_advice(self.helper, Rotation::prev());

            let padding_size_calc = padding_size.clone()
                - (padding_size_prev * Expression::Constant(F::from(256u64)) + byte);
            let final_must_padded = (one.clone()
                - meta.query_advice(self.s_padding, Rotation::cur()))
                * is_final.clone();

            let padding_size_is_zero =
                meta.query_selector(self.s_common_bytes) * padding_size.clone();

            // final contintion: byte counter equal to padding size
            let final_condition = meta.query_selector(self.s_final)
                * (padding_size
                    - (meta.query_advice(self.byte_counter, Rotation::cur())
                        * Expression::Constant(F::from(8u64))))
                * is_final.clone();

            let u16 = meta.query_advice(self.copied_data, Rotation::cur());
            let u16_exported = meta.query_advice(self.copied_data, Rotation::next());
            let init_iv_u16 = meta.query_fixed(self.s_output, Rotation::cur());
            let is_not_final = one.clone() - is_final.clone();

            let select_exported = meta.query_selector(self.s_assigned_u16)
                * (u16_exported - is_not_final * u16 - is_final * init_iv_u16);

            Constraints::with_selector(
                meta.query_selector(self.s_enable),
                vec![final_continue, final_is_bool],
            )
            .into_iter()
            .chain(Constraints::with_selector(
                meta.query_selector(self.s_padding_size),
                vec![final_must_padded, padding_size_calc],
            ))
            .chain(vec![
                padding_size_is_zero.into(),
                final_condition.into(),
                select_exported.into(),
            ])
        });

        meta.create_gate("input block beginning", |meta| {
            // is *last block* final
            let is_final = meta.query_advice(self.s_final_block, Rotation::prev());
            let is_not_final = one.clone() - is_final.clone();

            let inherited_counter = meta.query_advice(self.byte_counter, Rotation::prev());
            let byte_counter = meta.query_advice(self.byte_counter, Rotation::cur());

            let applied_counter = is_not_final.clone() * (byte_counter.clone() - inherited_counter)
                + is_final.clone() * byte_counter;

            let inherited_bytes_rlc = meta.query_advice(self.bytes_rlc, Rotation::prev());
            let bytes_rlc = meta.query_advice(self.bytes_rlc, Rotation::cur());

            let applied_bytes_rlc = is_not_final.clone()
                * (bytes_rlc.clone() - inherited_bytes_rlc)
                + is_final.clone() * bytes_rlc;

            let inherited_s_padding = meta.query_advice(self.s_padding, Rotation::prev());
            let s_padding = meta.query_advice(self.s_padding, Rotation::cur());

            let applied_s_padding = is_not_final.clone()
                * (s_padding.clone() - inherited_s_padding.clone())
                + is_final * s_padding;

            let is_final = meta.query_advice(self.s_final_block, Rotation::cur());
            let final_is_bool = is_final.clone() * (one.clone() - is_final.clone());

            // notice now the 'is_final' point to current block and 'is_not_final' point to last
            // block (prev) this constraint make circuit can not make a full block is
            // padded but not final
            let enforce_final = is_not_final * inherited_s_padding * (one.clone() - is_final);

            Constraints::with_selector(
                meta.query_selector(self.s_begin),
                vec![
                    final_is_bool,
                    applied_counter,
                    applied_bytes_rlc,
                    applied_s_padding,
                    enforce_final,
                ],
            )
        });
    }

    /// Configures a circuit to include this chip.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        sha256_table: impl SHA256Table,
        spec_challenge: Expression<F>,
    ) -> Self {
        let copied_data = meta.advice_column();
        let trans_byte = meta.advice_column();

        let final_output =  meta.advice_column();

        let bytes_rlc = sha256_table.hashes_rlc();
        let byte_counter = sha256_table.input_len();
        let helper = sha256_table.input_rlc();
        let s_output = sha256_table.s_enable();
        let s_final_block = sha256_table.is_effect();

        let s_padding_size = meta.selector();
        let s_padding = meta.advice_column();
        let s_begin = meta.selector();
        let s_common_bytes = meta.selector();
        let s_final = meta.selector();
        let s_enable = meta.selector();
        let s_assigned_u16 = meta.selector();

        let c_data = meta.fixed_column();
        let byte_range = meta.lookup_table_column();
        let table16 = Table16Chip::configure(meta);

        meta.enable_constant(c_data);
        meta.enable_equality(helper);
        meta.enable_equality(copied_data);
        meta.enable_equality(bytes_rlc);
        meta.enable_equality(s_final_block);
        meta.enable_equality(s_padding);
        meta.enable_equality(byte_counter);
        meta.enable_equality(final_output);

        let ret = Self {
            table16,
            byte_range,
            c_data,
            copied_data,
            trans_byte,
            bytes_rlc,
            helper,
            s_final_block,
            s_padding,
            byte_counter,
            s_output,
            final_output,
            s_begin,
            s_final,
            s_enable,
            s_common_bytes,
            s_padding_size,
            s_assigned_u16,
            _marker: PhantomData,
        };

        meta.lookup("byte range checking", |meta| {
            let byte = meta.query_advice(ret.trans_byte, Rotation::cur());
            vec![(byte, byte_range)]
        });

        ret.setup_gates(meta, spec_challenge);

        ret
    }

    #[allow(clippy::type_complexity)]
    fn assign_message_block<'vr>(
        &self,
        region: &mut Region<'_, F>,
        msgs: impl Iterator<Item = (&'vr AssignedBits<F, 16>, u16)>,
        offset: usize,
        is_final: bool,
    ) -> Result<(Vec<AssignedBits<F, 16>>, Vec<AssignedCell<F, F>>), Error> {
        let mut out_ret = Vec::new();
        let mut out_bytes = Vec::new();
        let mut size_calc = Value::known(F::ZERO);

        for (i, (msg, ref_iv)) in msgs.enumerate() {
            let row = offset + i * 2;
            let next_row = row + 1;

            self.s_assigned_u16.enable(region, row)?;

            msg.copy_advice(|| "copied message input", region, self.copied_data, row)?;
            let assigned = region.assign_advice(
                || "dummy message cell",
                self.copied_data,
                next_row,
                || {
                    if is_final {
                        Value::known(Bits::from(ref_iv))
                    } else {
                        msg.value().map(Clone::clone)
                    }
                },
            )?;

            let bytes_hi = region.assign_advice(
                || "u16 message hi byte",
                self.trans_byte,
                row,
                || msg.value().map(|v| F::from((u16::from(v) >> 8) as u64)),
            )?;

            let bytes_lo = region.assign_advice(
                || "u16 message lo byte",
                self.trans_byte,
                next_row,
                || {
                    msg.value()
                        .map(|v| F::from((u16::from(v) & 255u16) as u64))
                },
            )?;

            for (j, byte_v) in [&bytes_hi, &bytes_lo].into_iter().enumerate() {
                // bytes_rlc = region.assign_advice(
                //     || "bytes rlc",
                //     self.bytes_rlc,
                //     row + j,
                //     || chng * bytes_rlc.value() + byte_v.value(),
                // )?;

                // here we have a trick, since digest region has only 16 messages instead 32
                size_calc = region
                    .assign_advice(
                        || "padding size calc",
                        self.helper,
                        row + j,
                        || {
                            if i < 28 {
                                size_calc
                            } else {
                                size_calc.map(|v| v * F::from(256u64)) + byte_v.value()
                            }
                        },
                    )?
                    .value()
                    .map(Clone::clone);
            }

            out_bytes.push(bytes_hi);
            out_bytes.push(bytes_lo);
            out_ret.push(AssignedBits(assigned));
        }

        Ok((out_ret, out_bytes))
    }

    fn initialize_block_head(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<BlockInheritments<F>, Error> {
        layouter.assign_region(
            || "initialize hasher",
            |mut region| {
                let s_final = region.assign_advice_from_constant(
                    || "init s_final",
                    self.s_final_block,
                    0,
                    Bits::from([false]),
                )?;
                let s_padding = region.assign_advice_from_constant(
                    || "init padding",
                    self.s_padding,
                    0,
                    Bits::from([false]),
                )?;
                let bytes_rlc = region.assign_advice_from_constant(
                    || "init bytes rlc",
                    self.bytes_rlc,
                    0,
                    F::ZERO,
                )?;
                let byte_counter = region.assign_advice_from_constant(
                    || "init byte counter",
                    self.byte_counter,
                    0,
                    F::ZERO,
                )?;

                Ok(BlockInheritments {
                    s_final: AssignedBits(s_final),
                    s_padding: AssignedBits(s_padding),
                    byte_counter,
                    bytes_rlc,
                })
            },
        )
    }

    #[allow(clippy::type_complexity)]
    fn assign_input_block(
        &self,
        layouter: &mut impl Layouter<F>,
        chng: Value<F>,
        prev_block: BlockInheritments<F>,
        scheduled_msg: &[(AssignedBits<F, 16>, AssignedBits<F, 16>)],
        padding_pos: Option<usize>,
    ) -> Result<BlockInheritments<F>, Error> {
        // if no padding or the padding is in padding size pos, this block is not final
        let is_final = if let Some(pos) = padding_pos {
            pos < 56
        } else {
            false
        };

        let padding_pos = padding_pos.unwrap_or(64);

        layouter.assign_region(
            || "sha256 input",
            |mut region| {
                prev_block.s_final.copy_advice(
                    || "inherit s_final",
                    &mut region,
                    self.s_final_block,
                    0,
                )?;
                prev_block.s_padding.copy_advice(
                    || "inherit padding",
                    &mut region,
                    self.s_padding,
                    0,
                )?;
                prev_block.bytes_rlc.copy_advice(
                    || "inherit bytes rlc",
                    &mut region,
                    self.bytes_rlc,
                    0,
                )?;
                prev_block.byte_counter.copy_advice(
                    || "inherit byte counter",
                    &mut region,
                    self.byte_counter,
                    0,
                )?;

                self.s_begin.enable(&mut region, 1)?;
                let mut s_final_cell = region.assign_advice(
                    || "header final",
                    self.s_final_block,
                    1,
                    || Value::known(Bits::from([is_final])),
                )?;

                let mut s_padding_cell = region.assign_advice(
                    || "header padding",
                    self.s_padding,
                    1,
                    || {
                        prev_block
                            .s_final
                            .value()
                            .zip(prev_block.s_padding.value())
                            .map(|(s_final, ref_v)| {
                                if s_final[0] {
                                    Bits::from([false])
                                } else {
                                    ref_v.clone()
                                }
                            })
                    },
                )?;

                let mut byte_counter_cell = region.assign_advice(
                    || "header rlc",
                    self.byte_counter,
                    1,
                    || {
                        prev_block
                            .s_final
                            .value()
                            .zip(prev_block.byte_counter.value())
                            .map(|(s_final, ref_v)| if s_final[0] { F::ZERO } else { *ref_v })
                    },
                )?;

                let mut bytes_rlc_cell = region.assign_advice(
                    || "header counter",
                    self.bytes_rlc,
                    1,
                    || {
                        prev_block
                            .s_final
                            .value()
                            .zip(prev_block.bytes_rlc.value())
                            .map(|(s_final, ref_v)| if s_final[0] { F::ZERO } else { *ref_v })
                    },
                )?;

                let header_offset = 2;
                // assign message state
                let (_, byte_cells) = self.assign_message_block(
                    &mut region,
                    scheduled_msg
                        .iter()
                        .flat_map(|(lo, hi)| [hi, lo])
                        .zip(std::iter::repeat(0u16))
                        .take(32),
                    header_offset,
                    is_final,
                )?;

                for (row, byte) in (header_offset..(header_offset + 64)).zip(byte_cells) {
                    self.s_enable.enable(&mut region, row)?;
                    let now_padding = row >= padding_pos + header_offset;

                    region.assign_fixed(
                        || "flush s_output",
                        self.s_output,
                        row,
                        || Value::known(F::ZERO),
                    )?;
                    s_padding_cell = region.assign_advice(
                        || "padding",
                        self.s_padding,
                        row,
                        || Value::known(Bits::from([now_padding])),
                    )?;
                    s_final_cell = region.assign_advice(
                        || "final",
                        self.s_final_block,
                        row,
                        || s_final_cell.value().map(Clone::clone),
                    )?;
                    byte_counter_cell = region.assign_advice(
                        || "byte counter",
                        self.byte_counter,
                        row,
                        || {
                            byte_counter_cell.value().map(Clone::clone)
                                + Value::known(if now_padding { F::from(0u64) } else { F::from(1u64)  })
                        },
                    )?;
                    bytes_rlc_cell = region.assign_advice(
                        || "bytes rlc",
                        self.bytes_rlc,
                        row,
                        || {
                            if now_padding {
                                bytes_rlc_cell.value().map(Clone::clone)
                            } else {
                                chng * bytes_rlc_cell.value() + byte.value()
                            }
                        },
                    )?;

                    // println!("padding {:#?}, counter {:#?} at row {}",
                    // output_block.s_padding.value(), output_block.byte_counter.value(), row);
                    // println!("final {:#?}, at row {}", output_block.s_final.value(), row);

                    if row < 56 + header_offset {
                        self.s_common_bytes.enable(&mut region, row)?;
                    } else {
                        self.s_padding_size.enable(&mut region, row)?;
                    }
                }
                self.s_final.enable(&mut region, 63 + header_offset)?;

                // flush unused row
                for col in [self.trans_byte, self.copied_data] {
                    region.assign_advice(
                        || "flush unused row",
                        col,
                        64 + header_offset,
                        || Value::known(F::ZERO),
                    )?;
                }

                region.assign_advice(
                    || "flush unused row",
                    self.helper,
                    1,
                    || Value::known(F::ZERO),
                )?;

                Ok(BlockInheritments {
                    s_final: AssignedBits(s_final_cell),
                    s_padding: AssignedBits(s_padding_cell),
                    byte_counter: byte_counter_cell,
                    bytes_rlc: bytes_rlc_cell,
                })
            },
        )
    }

    const IV16: [u16; 16] = [
        0x6a09, 0xe667, 0xbb67, 0xae85, 0x3c6e, 0xf372, 0xa54f, 0xf53a, 0x510e, 0x527f, 0x9b05,
        0x688c, 0x1f83, 0xd9ab, 0x5be0, 0xcd19,
    ];

    #[allow(clippy::type_complexity)]
    fn assign_output_region(
        &self,
        layouter: &mut impl Layouter<F>,
        chng: Value<F>,
        state: &[(AssignedBits<F, 16>, AssignedBits<F, 16>)],
        input_block: &BlockInheritments<F>,
        is_final: bool,
    ) -> Result<[(AssignedBits<F, 16>, AssignedBits<F, 16>); 8], Error> {
        let output_cells = layouter.assign_region(
            || "sha256 digest",
            |mut region| {
                input_block.s_final.copy_advice(
                    || "inherit s_final",
                    &mut region,
                    self.s_final_block,
                    0,
                )?;
                region.assign_advice_from_constant(
                    || "header padding",
                    self.s_padding,
                    0,
                    F::ZERO,
                )?;
                region.assign_advice_from_constant(
                    || "header counter",
                    self.byte_counter,
                    0,
                    F::ZERO,
                )?;
                let mut digest_rlc = region.assign_advice_from_constant(
                    || "header rlc",
                    self.bytes_rlc,
                    0,
                    F::ZERO,
                )?;

                let header_offset = 1;
                // assign message state
                let (export_cells, byte_cells) = self.assign_message_block(
                    &mut region,
                    state
                        .iter()
                        .flat_map(|(lo, hi)| [hi, lo])
                        .zip_eq(Self::IV16),
                    header_offset,
                    is_final,
                )?;

                for (i, byte_cell) in byte_cells.iter().enumerate().take(32) {
                    let row = i + header_offset;
                    self.s_enable.enable(&mut region, row)?;
                    region.assign_fixed(
                        || "set s_output for init_iv",
                        self.s_output,
                        row,
                        || Value::known(F::from(Self::IV16[i / 2] as u64)),
                    )?;
                    region.assign_advice(
                        || "byte counter",
                        self.byte_counter,
                        row,
                        || Value::known(F::from(i as u64 + 1)),
                    )?;
                    region.assign_advice(
                        || "final",
                        self.s_final_block,
                        row,
                        || Value::known(Bits::from([is_final])),
                    )?;
                    digest_rlc = region.assign_advice(
                        || "bytes rlc",
                        self.bytes_rlc,
                        row,
                        || chng * digest_rlc.value() + byte_cell.value(),
                    )?;
                    // with gate for padding continue, it
                    // is enough to constraint the last padding as 0
                    if i == 31 {
                        region.assign_advice_from_constant(
                            || "dummy padding last",
                            self.s_padding,
                            row,
                            F::ZERO,
                        )?;
                    } else {
                        region.assign_advice(
                            || "dummy padding",
                            self.s_padding,
                            row,
                            || Value::known(F::ZERO),
                        )?;
                    }
                }

                // build output row
                let final_row = header_offset + 32;
                region.assign_fixed(
                    || "mark s_output final",
                    self.s_output,
                    final_row,
                    || Value::known(F::ONE),
                )?;
                digest_rlc.copy_advice(
                    || "copy digest rlc",
                    &mut region,
                    self.bytes_rlc,
                    final_row,
                )?;
                input_block.bytes_rlc.copy_advice(
                    || "copy input rlc",
                    &mut region,
                    self.helper,
                    final_row,
                )?;
                input_block.byte_counter.copy_advice(
                    || "copy bytes",
                    &mut region,
                    self.byte_counter,
                    final_row,
                )?;
                input_block.s_final.copy_advice(
                    || "copy final",
                    &mut region,
                    self.s_final_block,
                    final_row,
                )?;

                for col in [self.trans_byte, self.copied_data] {
                    region.assign_advice(
                        || "flush unused row",
                        col,
                        final_row,
                        || Value::known(F::ZERO),
                    )?;
                }

                region.assign_advice(
                    || "flush unused row",
                    self.helper,
                    0,
                    || Value::known(F::ZERO),
                )?;

                Ok(export_cells
                    .chunks_exact(2)
                    .map(|ck_pair| (ck_pair[1].clone(), ck_pair[0].clone()))
                    .collect::<Vec<_>>())
            },
        )?;

        Ok(output_cells.try_into().unwrap())
    }

    fn initialize_constant_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "byte range constant",
            |mut tb| {
                for i in 0..256 {
                    tb.assign_cell(
                        || "byte range",
                        self.byte_range,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }
}

/// sha256 hasher for byte stream
#[derive(Debug)]
pub struct Hasher<F: PrimeField> {
    chip: CircuitConfig<F>,
    state: <Table16Chip as Sha256Instructions<F>>::State,
    hasher_state: BlockInheritments<F>,
    cur_block: Vec<u8>,
    length: usize,
    block_usage: usize,
}

impl<F: PrimeField> Hasher<F>  {
    /// return the number of 512-bit blocks which has been assigned
    pub fn blocks(&self) -> usize {
        self.block_usage
    }

    /// return the number bytes current update, 0 indicate a clean status
    pub fn updated_size(&self) -> usize {
        self.length
    }

    /// create a hasher, the circuit would be identify when block_usage is the same
    pub fn new(chip: CircuitConfig<F>, layouter: &mut impl Layouter<F>) -> Result<Self, Error> {
        // constant part
        chip.initialize_constant_table(layouter)?;
        Table16Chip::load(chip.table16.clone(), layouter)?;

        let table16_chip = Table16Chip::construct::<F>(chip.table16.clone());
        let state = table16_chip.initialization_vector(layouter)?;
        // init the 16 iv cells and binding them to initialize state
        layouter.assign_region(
            || "sha256 state initialized by iv bind",
            |mut region| {
                let extract_dense = {
                    let (a, b, c, d, e, f, g, h) = match state.clone() {
                        Table16State::Compress(s) => s.decompose(),
                        _ => unreachable!(),
                    };
                    [
                        a.into_dense(),
                        b.into_dense(),
                        c.into_dense(),
                        d,
                        e.into_dense(),
                        f.into_dense(),
                        g.into_dense(),
                        h,
                    ]
                };
                for (i, den_s) in extract_dense.into_iter().enumerate() {
                    let (cell_s_lo, cell_s_hi) = den_s.decompose();
                    let row_i = i * 2;
                    // notice the iv is organized as (hi, lo)
                    let (iv_hi, iv_lo) =
                        (CircuitConfig::<F>::IV16[row_i], CircuitConfig::<F>::IV16[row_i + 1]);
                    let (cell_iv_lo, cell_iv_hi) = (
                        region.assign_fixed(
                            || "iv_hi",
                            chip.c_data,
                            row_i,
                            || Value::known(F::from(iv_lo as u64)),
                        )?,
                        region.assign_fixed(
                            || "iv_hi",
                            chip.c_data,
                            row_i + 1,
                            || Value::known(F::from(iv_hi as u64)),
                        )?,
                    );
                    region.constrain_equal(cell_s_lo.cell(), cell_iv_lo.cell())?;
                    region.constrain_equal(cell_s_hi.cell(), cell_iv_hi.cell())?;
                }

                Ok(())
            },
        )?;

        let hasher_state = chip.initialize_block_head(layouter)?;
        Ok(Self {
            chip,
            state,
            hasher_state,
            cur_block: Vec::with_capacity(BLOCK_SIZE * 4),
            length: 0,
            block_usage: 0,
        })
    }

    /// update a single 512-bit block into layouter
    fn update_block(
        &mut self,
        layouter: &mut impl Layouter<F>,
        chng: Value<F>,
        input: [BlockWord; BLOCK_SIZE],
        padding: Option<usize>,
        is_final: bool,
    ) -> Result<<Table16Chip as Sha256Instructions<F>>::State, Error> {
        let table16_cfg = &self.chip.table16;

        let w_halves = table16_cfg.message_process(layouter, input)?;

        let init_working_state = match &self.state {
            Table16State::Compress(s) => s.as_ref().clone(),
            Table16State::Dense(s) => {
                // for the state cells being initialized, we should just
                // need to constraint the "dense" cell and the relationships
                // among the vars / spread cells is handled by compression
                // gadget
                let s_inited = table16_cfg.initialize(layouter, s.clone())?;

                // limited by the halo2's entry, we need a empyt region
                // to bind the input and output initialized cells
                layouter.assign_region(
                    || "sha256 state initialized bind",
                    |mut region| {
                        let extract_dense = {
                            let (a, b, c, d, e, f, g, h) = s_inited.clone().decompose();
                            [
                                a.into_dense(),
                                b.into_dense(),
                                c.into_dense(),
                                d,
                                e.into_dense(),
                                f.into_dense(),
                                g.into_dense(),
                                h,
                            ]
                        };
                        for (den_inp, den_assigned) in s.clone().into_iter().zip(extract_dense) {
                            let (cell_inp_1, cell_inp_2) = den_inp.decompose();
                            let (cell_assigned_1, cell_assigned_2) = den_assigned.decompose();

                            region.constrain_equal(cell_inp_1.cell(), cell_assigned_1.cell())?;
                            region.constrain_equal(cell_inp_2.cell(), cell_assigned_2.cell())?;
                        }

                        Ok(())
                    },
                )?;

                s_inited
            }
        };

        self.hasher_state = self.chip.assign_input_block(
            layouter,
            chng,
            self.hasher_state.clone(),
            &w_halves[..16],
            padding,
        )?;

        let compress_state =
            table16_cfg.compress(layouter, init_working_state.clone(), w_halves)?;
        let digest_state = table16_cfg.digest(layouter, compress_state, init_working_state)?;

        self.state = self
            .chip
            .assign_output_region(
                layouter,
                chng,
                &digest_state.clone().map(|v| v.decompose()),
                &self.hasher_state,
                is_final,
            )
            .map(|s| s.map(|v| v.into()))
            .map(Table16State::Dense)?;
        self.block_usage += 1;

        Ok(Table16State::Dense(digest_state))
    }

    fn block_transform(bytes: &[u8]) -> Vec<BlockWord> {
        assert_eq!(bytes.len(), BLOCK_SIZE * 4);
        bytes
            .chunks_exact(4)
            .map(|bt| bt.iter().fold(0u32, |sum, v| sum * 256 + *v as u32))
            .map(Value::known)
            .map(BlockWord)
            .collect::<Vec<_>>()
    }

    /// Digest data, updating the internal state.
    pub fn update(
        &mut self,
        layouter: &mut impl Layouter<F>,
        chng: Value<F>,
        mut data: &[u8],
    ) -> Result<(), Error> {
        use std::cmp::min;

        self.length += data.len();

        // Fill the current block, if possible.
        let remaining = BLOCK_SIZE * 4 - self.cur_block.len();
        let (l, r) = data.split_at(min(remaining, data.len()));
        self.cur_block.extend_from_slice(l);
        data = r;

        // If we still don't have a full block, we are done.
        if self.cur_block.len() < BLOCK_SIZE * 4 {
            return Ok(());
        }

        // transform to word block
        let word_block = Self::block_transform(&self.cur_block);

        // Process the now-full current block.
        self.update_block(
            layouter,
            chng,
            word_block.as_slice().try_into().unwrap(),
            None,
            false,
        )?;

        self.cur_block.clear();

        // Process any additional full blocks.
        let mut chunks_iter = data.chunks_exact(BLOCK_SIZE * 4);
        for chunk in &mut chunks_iter {
            let word_block = Self::block_transform(chunk);
            self.update_block(
                layouter,
                chng,
                word_block.as_slice().try_into().unwrap(),
                None,
                false,
            )?;
        }

        // Cache the remaining partial block, if any.
        let rem = chunks_iter.remainder();
        self.cur_block.extend_from_slice(rem);

        Ok(())
    }

    /// generate the final digest and ready for new update.
    pub fn finalize(
        &mut self,
        layouter: &mut impl Layouter<F>,
        chng: Value<F>,
    ) -> Result<[AssignedCell<F, F>; DIGEST_SIZE], Error> /*Result<[BlockWord; DIGEST_SIZE], Error> */ {
        // check padding requirement
        let mut padding_pos = Some(self.cur_block.len());

        // of course we have at least 1 byte left (or cur_block would have been compressed)
        // push the additional 1bit
        self.cur_block.push(128);
        let remaining = BLOCK_SIZE * 4 - self.cur_block.len();

        // if we have no enough space (64bit)， we need a extra block
        if remaining < 8 {
            self.cur_block.resize(BLOCK_SIZE * 4, 0u8);
            let word_block = Self::block_transform(&self.cur_block);

            self.update_block(
                layouter,
                chng,
                word_block.as_slice().try_into().unwrap(),
                padding_pos,
                false,
            )?;

            padding_pos = Some(0);
            self.cur_block.clear();
        }

        self.cur_block.resize(BLOCK_SIZE * 4 - 8, 0u8);
        self.cur_block
            .extend(((self.length * 8) as u64).to_be_bytes());
        assert_eq!(self.cur_block.len(), BLOCK_SIZE * 4);

        let word_block = Self::block_transform(&self.cur_block);

        let digest_state = self.update_block(
            layouter,
            chng,
            word_block.as_slice().try_into().unwrap(),
            padding_pos,
            true,
        )?;
        self.cur_block.clear();
        self.length = 0;

        let digest_state = match digest_state {
            Table16State::Dense(s) => s,
            _ => panic!("unexpected state type"),
        };

        let final_output_cells = layouter.assign_region(
            || "set final output",
            |mut region| {
                let mut cells_  = Vec::new();
                for offset in 0..8 {
                    //let t = Value::known(F::ZERO) ;
                    let vall = digest_state[offset].value().map(|value| F::from(value as u64));
                    let cell = region
                    .assign_advice(|| "", self.chip.final_output, offset, || vall)
                    .expect("assign copy advice should not fail");
                    
                    cells_.push(cell);

                }
                Ok(cells_)
            }
        ).unwrap();

        let final_output_cells: [AssignedCell<F, F>; DIGEST_SIZE] = final_output_cells.try_into().unwrap();

        Ok(final_output_cells)
        
        //Ok(digest_state.map(|s| s.value()).map(BlockWord))
    }
}
