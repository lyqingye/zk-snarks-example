use bls12_381::{Bls12, Scalar};
use ff::PrimeField;
use rand::thread_rng;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof};

/// x^3 + x + 5 == out
#[allow(clippy::upper_case_acronyms)]
pub struct DemoCircuit< S: PrimeField> {
    pub x: S,
}

impl<S: PrimeField> Circuit<S> for DemoCircuit< S> {
    fn synthesize<CS: ConstraintSystem<S>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let x_value = self.x;
        let x = cs.alloc(|| "x", || Ok(self.x))?;

        let sym_1_value = x_value * x_value;
        let sym_1 = cs.alloc(|| "sym_1", || Ok(sym_1_value))?;

        cs.enforce(
            || "sym_1 = x * x",
            |lc| lc + x,
            |lc| lc + x,
            |lc| lc + sym_1,
        );

        let y_value = sym_1_value * x_value;
        let y = cs.alloc(|| "y", || Ok(y_value))?;
        cs.enforce(
            || "y = sym_1 * x",
            |lc| lc + sym_1,
            |lc| lc + x,
            |lc| lc + y,
        );

        let sym_2_value = x_value + y_value;
        let sym_2 = cs.alloc(|| "sym_2", || Ok(sym_2_value))?;
        cs.enforce(
            || "sym_2 = (x + y) * 1",
            |lc| lc + x + y,
            |lc| lc + CS::one(),
            |lc| lc + sym_2,
        );

        let cons_five_value = S::from(5);

        let out_value = sym_2_value + cons_five_value;
        let out = cs.alloc(|| "out", || Ok(out_value))?;
        cs.enforce(
            || "out = (sym_2 + 5) * 1",
            |lc| lc + sym_2 + (cons_five_value, CS::one()),
            |lc| lc + CS::one(),
            |lc| lc + out,
        );

        cs.alloc_input(
            || "out",
            || Ok(out_value),
        )?;
        Ok(())
    }
}

fn main() {
    let mut rng = thread_rng();
    let c1 = DemoCircuit {
        x: Scalar::default(),
    };

    let params = generate_random_parameters::<Bls12, _, _>(c1, &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);

    let c2 = DemoCircuit {
        x: Scalar::from(3),
    };

    let proof = create_random_proof(c2, &params, &mut rng).unwrap();
    verify_proof(&pvk, &proof, &[Scalar::from(35)]).unwrap();
}
