use group::{Group, ff::PrimeField};
use oprf::{Input, Suite, VerifyingKey, client::Client, mode, server::Server};

pub trait Mode {
    type VerifyingKey<E>;
    type VectorData<S>;
}

impl Mode for oprf::mode::Base {
    type VerifyingKey<E> = ();

    type VectorData<S> = ();
}

impl Mode for oprf::mode::Verifiable {
    type VerifyingKey<E> = VerifyingKey<E>;

    type VectorData<S> = VerifiableData<S>;
}

impl Mode for oprf::mode::Partial {
    type VerifyingKey<E> = VerifyingKey<E>;

    type VectorData<S> = PartialData<S>;
}

pub struct VerifiableData<S> {
    pub proof: oprf::Proof<S>,
    pub proof_scalar: S,
}

pub struct PartialData<S> {
    pub verifiable_data: VerifiableData<S>,
    pub info: Vec<u8>,
}

pub struct Vectors<const N: usize, S: Suite, M: Mode> {
    pub seed: [u8; 32],
    pub info: Vec<u8>,
    pub secret_key: <S::Group as Group>::Scalar,
    pub verifying_key: M::VerifyingKey<S::Group>,
    pub vectors: Box<[Vector<N, S, M>]>,
}

pub struct Vector<const N: usize, S: Suite, M: Mode> {
    pub inputs: [Vec<u8>; N],
    pub blinds: [<S::Group as Group>::Scalar; N],
    pub blinded_elements: [S::Group; N],
    pub evaluated_elements: [S::Group; N],
    pub outputs: [Vec<u8>; N],
    pub vector_data: M::VectorData<<S::Group as Group>::Scalar>,
}

impl<const N: usize, S: Suite> Vectors<N, S, mode::Base> {
    pub fn test(&self) {
        let server =
            Server::<S, mode::Base>::new(self.seed, Input::try_from(&self.info[..]).unwrap())
                .unwrap();
        assert_eq!(server.secret_key(), &self.secret_key);

        for vector in &self.vectors {
            let inputs: [_; N] = vector
                .inputs
                .iter()
                .map(|i| Input::try_from(&i[..]).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let blind_reprs = vector.blinds.map(|b| b.to_repr());
            let mut rng = TestRng::new(blind_reprs.each_ref().map(|b| b.as_ref()));

            let (client, blinded_elements) =
                Client::<_, S, mode::Base>::blind(inputs, &mut rng).unwrap();
            assert_eq!(blinded_elements.map(|b| b.0), vector.blinded_elements);
            let evaluated_elements = server.evaluate(blinded_elements);
            assert_eq!(evaluated_elements.map(|e| e.0), vector.evaluated_elements);
            let outputs = client.finalize(evaluated_elements);
            outputs
                .iter()
                .zip(&vector.outputs)
                .for_each(|(a, b)| assert_eq!(a.as_slice(), b.as_slice(), "outputs should match"));
        }
    }
}

impl<const N: usize, S: Suite> Vectors<N, S, mode::Verifiable> {
    pub fn test(&self) {
        let server =
            Server::<S, mode::Verifiable>::new(self.seed, Input::try_from(&self.info[..]).unwrap())
                .unwrap();
        assert_eq!(server.secret_key(), &self.secret_key);
        assert_eq!(server.verifying_key(), self.verifying_key);

        for vector in &self.vectors {
            let inputs: [_; N] = vector
                .inputs
                .iter()
                .map(|i| Input::try_from(&i[..]).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let blind_reprs = vector.blinds.map(|b| b.to_repr());
            let mut rng = TestRng::new(blind_reprs.each_ref().map(|b| b.as_ref()));

            let (client, blinded_elements) =
                Client::<_, S, mode::Verifiable>::blind(inputs, server.verifying_key(), &mut rng)
                    .unwrap();
            assert_eq!(blinded_elements.map(|b| b.0), vector.blinded_elements);

            let proof_scalar_repr = vector.vector_data.proof_scalar.to_repr();
            let mut rng = TestRng::new([proof_scalar_repr.as_ref()]);
            let (evaluated_elements, proof) = server.evaluate(blinded_elements, &mut rng);
            assert_eq!(evaluated_elements.map(|e| e.0), vector.evaluated_elements);
            assert_eq!(proof, vector.vector_data.proof);
            let outputs = client.finalize(evaluated_elements, proof).unwrap();
            outputs
                .iter()
                .zip(&vector.outputs)
                .for_each(|(a, b)| assert_eq!(a.as_slice(), b.as_slice(), "outputs should match"));
        }
    }
}

impl<const N: usize, S: Suite> Vectors<N, S, mode::Partial> {
    pub fn test(&self) {
        let server =
            Server::<S, mode::Partial>::new(self.seed, Input::try_from(&self.info[..]).unwrap())
                .unwrap();
        assert_eq!(server.secret_key(), &self.secret_key);
        assert_eq!(server.verifying_key(), self.verifying_key);

        for vector in &self.vectors {
            let inputs: [_; N] = vector
                .inputs
                .iter()
                .map(|i| Input::try_from(&i[..]).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let info = Input::try_from(vector.vector_data.info.as_ref()).unwrap();

            let blind_reprs = vector.blinds.map(|b| b.to_repr());
            let mut rng = TestRng::new(blind_reprs.each_ref().map(|b| b.as_ref()));

            let (client, blinded_elements) = Client::<_, S, mode::Partial>::blind(
                inputs,
                info,
                server.verifying_key(),
                &mut rng,
            )
            .unwrap();
            assert_eq!(blinded_elements.map(|b| b.0), vector.blinded_elements);

            let proof_scalar_repr = vector.vector_data.verifiable_data.proof_scalar.to_repr();
            let mut rng = TestRng::new([proof_scalar_repr.as_ref()]);
            let (evaluated_elements, proof) =
                server.evaluate(blinded_elements, info, &mut rng).unwrap();
            assert_eq!(evaluated_elements.map(|e| e.0), vector.evaluated_elements);
            assert_eq!(proof, vector.vector_data.verifiable_data.proof);
            let outputs = client.finalize(evaluated_elements, proof).unwrap();
            outputs
                .iter()
                .zip(&vector.outputs)
                .for_each(|(a, b)| assert_eq!(a.as_slice(), b.as_slice(), "outputs should match"));
        }
    }
}

/// Parse a vector from the RFC with minimal formatting required.
/// The only modification from the vectors in the RFC are the quotes added to the values,
/// the dash after the output field, and the ordering of the fields.
macro_rules! parse_vectors {
    (<$suite:ty, $mode:ident>:
         Seed = $seed:literal
         KeyInfo = $info:literal
         skSm = $secret_key:literal
         $($rest:tt)*
    ) => {
        vector::Vectors::<_, $suite, $mode> {
            seed: const_hex::decode_to_array($seed).unwrap(),
            info: const_hex::decode($info).unwrap(),
            secret_key: <<$suite as oprf::Suite>::Group as group::Group>::Scalar::from_repr(
                TryFrom::try_from(&const_hex::decode($secret_key).unwrap()[..]).unwrap(),
            )
            .unwrap(),
            verifying_key: parse_vectors! { @verifying_key<$suite, $mode>  $($rest)* },
            vectors: parse_vectors! { @vectors<$suite, $mode>  $($rest)* },
        }
    };

    (@verifying_key<$suite:ty, Base> [ $($rest:tt)* ]) => {
        ()
    };
    (@verifying_key<$suite:ty, $mode:ident> pkSm = $verifying_key:literal [ $($rest:tt)* ]) => {
        oprf::VerifyingKey(<<$suite as oprf::Suite>::Group as group::GroupEncoding>::from_bytes(
            TryFrom::try_from(&const_hex::decode(
                $verifying_key
            ).unwrap()[..]).unwrap(),
        ).unwrap())
    };

    (@vectors<$suite:ty, $mode:ident> $(pkSm = $_ignore:literal)? [
        $({
            Input = $( $input:literal ),+
            Blind = $( $blind:literal ),+
            BlindedElement = $( $blinded:literal ),+
            EvaluationElement = $( $evaluated:literal ),+
            Output = $( $output:literal ),+ -
            $($rest:tt)*
        }),*
    ]) => {
        Box::new([
            $(
                vector::Vector::<_, $suite, $mode> {
                    inputs: [ $( const_hex::decode($input).unwrap() ),+ ],
                    blinds: [ $( <<$suite as oprf::Suite>::Group as group::Group>::Scalar::from_repr(
                        TryFrom::try_from(&const_hex::decode($blind).unwrap()[..]).unwrap(),
                    ).unwrap() ),* ],
                    blinded_elements: [ $( <<$suite as oprf::Suite>::Group as group::GroupEncoding>::from_bytes(
                        TryFrom::try_from(&const_hex::decode($blinded).unwrap()[..]).unwrap(),
                    ).unwrap() ),* ],
                    evaluated_elements: [ $( <<$suite as oprf::Suite>::Group as group::GroupEncoding>::from_bytes(
                        TryFrom::try_from(&const_hex::decode($evaluated).unwrap()[..]).unwrap(),
                    ).unwrap() ),* ],
                    outputs: [ $( const_hex::decode($output).unwrap() ),+ ],
                    vector_data: parse_vectors! { @vector_data<$suite, $mode>  $($rest)* },
                }
            ),*
        ])
    };

    (@vector_data<$suite:ty, Base>  $($rest:tt)*) => {
        ()
    };

    (@vector_data<$suite:ty, Verifiable> Proof = $proof:literal ProofRandomScalar = $proof_scalar:literal) => {
        vector::VerifiableData {
            proof: {
                let bytes = const_hex::decode($proof).unwrap();
                let len = <<<<<$suite as oprf::Suite>::Group as group::Group>::Scalar as group::ff::PrimeField>::Repr as digest::array::AssocArraySize>::Size as digest::typenum::Unsigned>::USIZE;
                oprf::Proof {
                    c: <<$suite as oprf::Suite>::Group as group::Group>::Scalar::from_repr(
                        TryFrom::try_from(&bytes[..len]).unwrap(),
                    ).unwrap(),
                    s: <<$suite as oprf::Suite>::Group as group::Group>::Scalar::from_repr(
                        TryFrom::try_from(&bytes[len..]).unwrap(),
                    ).unwrap(),
                }
            },
            proof_scalar: <<$suite as oprf::Suite>::Group as group::Group>::Scalar::from_repr(
                TryFrom::try_from(&const_hex::decode($proof_scalar).unwrap()[..]).unwrap(),
            ).unwrap(),
        }
    };

    (@vector_data<$suite:ty, Partial> Proof = $proof:literal ProofRandomScalar = $proof_scalar:literal Info = $info:literal) => {
        vector::PartialData {
            verifiable_data: parse_vectors! { @vector_data<$suite, Verifiable> Proof = $proof ProofRandomScalar = $proof_scalar },
            info: const_hex::decode($info).unwrap(),
        }
    };
}
pub(crate) use parse_vectors;

use rand_core::{CryptoRng, RngCore};

/// Generate bytes to seed random scalars.
pub struct TestRng<'a, const N: usize>([&'a [u8]; N], usize);

impl<'a, const N: usize> TestRng<'a, N> {
    /// Create a new `TestRng` with the given byte slices.
    pub fn new(slices: [&'a [u8]; N]) -> Self {
        Self(slices, 0)
    }
}

impl<const N: usize> RngCore for TestRng<'_, N> {
    fn next_u32(&mut self) -> u32 {
        panic!("not needed")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("not needed")
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        let len = self.0[self.1].len();
        let (begin, end) = dst.split_at_mut(len);
        begin.copy_from_slice(self.0[self.1]);
        end.fill(0);
        self.1 += 1;
    }
}

impl<const N: usize> CryptoRng for TestRng<'_, N> {}

// Test that the RNG produces the expected scalar values.
//
// #[test]
// fn ristretto_rng() {
//     let bytes =
//         const_hex::decode("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e")
//             .unwrap();
//     let mut rng = TestRng([&bytes[..]], 0);
//     let scalar = curve25519_dalek::scalar::Scalar::random(&mut rng);
//     assert_eq!(
//         scalar.to_bytes(),
//         bytes.as_slice(),
//         "RNG should produce the same bytes"
//     );
// }
//
// #[test]
// fn decaf_rng() {
//     let bytes = const_hex::decode("b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b").unwrap();
//     let mut rng = TestRng([&bytes[..]], 0);
//     let scalar = ed448_goldilocks::DecafScalar::random(&mut rng);
//     assert_eq!(
//         scalar.to_bytes(),
//         bytes.as_slice(),
//         "RNG should produce the same bytes"
//     );
// }
//
// #[test]
// fn p256_rng() {
//     let bytes = const_hex::decode("f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1").unwrap();
//     let mut rng = TestRng([&bytes[..]], 0);
//     let scalar = p256::Scalar::random(&mut rng);
//     assert_eq!(
//         scalar.to_bytes().as_slice(),
//         bytes.as_slice(),
//         "RNG should produce the same bytes"
//     );
// }
