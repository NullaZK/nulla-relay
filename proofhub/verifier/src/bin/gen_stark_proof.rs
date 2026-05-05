/// Standalone binary: generate a STARK range proof for a given value.
/// Outputs the proof wire bytes as hex to stdout.
///
/// Usage: gen_stark_proof <value_u64>
///
/// Wire format output (matches verify_range_proof expectation for 1 commitment):
///   byte[0]:   n=1
///   [u32 LE]:  proof_len
///   [proof]:   STARK proof bytes
///   [u64 LE]:  value

use std::env;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, BatchingMethod, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, FieldExtension, ProofOptions,
    Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
    matrix::ColMatrix,
    CompositionPolyTrace, CompositionPoly, PartitionOptions,
    DefaultConstraintCommitment, AuxRandElements,
};

const STARK_RANGE_BITS: usize = 64;
const STARK_TRACE_LEN: usize = 128;

type H = Blake3_256<BaseElement>;
type VC = MerkleTree<H>;
type RC = DefaultRandomCoin<H>;

#[derive(Clone)]
struct RangePub { value: u64 }

impl ToElements<BaseElement> for RangePub {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![BaseElement::new(self.value as u128)]
    }
}

struct RangeAir {
    ctx: AirContext<BaseElement>,
    value: u64,
}

impl Air for RangeAir {
    type BaseField = BaseElement;
    type PublicInputs = RangePub;

    fn new(trace_info: TraceInfo, pub_inputs: RangePub, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
        ];
        RangeAir {
            ctx: AirContext::new(trace_info, degrees, 3, options),
            value: pub_inputs.value,
        }
    }

    fn context(&self) -> &AirContext<BaseElement> { &self.ctx }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self, frame: &EvaluationFrame<E>, _: &[E], result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        result[0] = cur[0] * (cur[0] - E::ONE);
        result[1] = nxt[1] - (cur[1] + cur[0] * cur[2]);
        result[2] = nxt[2] - cur[2].double();
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        vec![
            Assertion::single(1, 0, BaseElement::ZERO),
            Assertion::single(2, 0, BaseElement::ONE),
            Assertion::single(1, STARK_RANGE_BITS, BaseElement::new(self.value as u128)),
        ]
    }
}

struct RangeProver { options: ProofOptions, value: u64 }

impl RangeProver {
    fn new(value: u64) -> Self {
        RangeProver {
            value,
            options: ProofOptions::new(28, 8, 0, FieldExtension::None, 8, 127,
                BatchingMethod::Linear, BatchingMethod::Horner),
        }
    }

    fn build_trace(&self) -> TraceTable<BaseElement> {
        let bits: Vec<u64> = (0..STARK_RANGE_BITS).map(|i| (self.value >> i) & 1).collect();
        let mut trace = TraceTable::new(3, STARK_TRACE_LEN);
        trace.fill(
            |state| {
                state[0] = BaseElement::new(bits[0] as u128);
                state[1] = BaseElement::ZERO;
                state[2] = BaseElement::ONE;
            },
            |step, state| {
                let prev_bit = state[0];
                let prev_psum = state[1];
                let prev_power = state[2];
                state[1] = prev_psum + prev_bit * prev_power;
                state[2] = prev_power.double();
                let next_step = step + 1;
                state[0] = if next_step < STARK_RANGE_BITS {
                    BaseElement::new(bits[next_step] as u128)
                } else {
                    BaseElement::new((next_step & 1) as u128)
                };
            },
        );
        trace
    }
}

impl Prover for RangeProver {
    type BaseField = BaseElement;
    type Air = RangeAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = VC;
    type RandomCoin = RC;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, H, VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, RangeAir, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, H, VC>;

    fn options(&self) -> &ProofOptions { &self.options }

    fn get_pub_inputs(&self, _trace: &TraceTable<BaseElement>) -> RangePub {
        RangePub { value: self.value }
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self, trace_info: &TraceInfo, main_trace: &ColMatrix<Self::BaseField>, domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self, air: &'a RangeAir, aux_rand_elements: Option<AuxRandElements<E>>, composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self, composition_poly_trace: CompositionPolyTrace<E>, num_constraint_composition_columns: usize, domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(composition_poly_trace, num_constraint_composition_columns, domain, partition_options)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let value: u64 = if args.len() > 1 {
        args[1].parse().expect("value must be a u64")
    } else {
        42u64
    };

    let prover = RangeProver::new(value);
    let trace = prover.build_trace();
    let proof = prover.prove(trace).expect("proof generation failed");
    let proof_bytes = proof.to_bytes();

    // Build wire format: [n=1][proof_len u32 LE][proof_bytes][value u64 LE]
    let mut wire: Vec<u8> = Vec::new();
    wire.push(1u8); // n_proofs = 1
    let proof_len = proof_bytes.len() as u32;
    wire.extend_from_slice(&proof_len.to_le_bytes());
    wire.extend_from_slice(&proof_bytes);
    wire.extend_from_slice(&value.to_le_bytes());

    // Output as hex to stdout
    print!("{}", hex::encode(&wire));
}
