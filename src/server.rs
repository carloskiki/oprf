use group::{Group, ff::Field};
use rand_core::RngCore;

use crate::{
    Blind, Evaluated, Proof, Suite, VerifyingKey, context_string, generate_proof, hash_to_scalar,
    input::Input,
    mode::{self, Mode},
};

/// The server of the protocol.
#[allow(private_bounds)]
pub struct Server<S: Suite, M: Mode> {
    key: <S::Group as Group>::Scalar,
    payload: M::ServerPayload<S::Group>,
}

#[allow(private_bounds)]
impl<S: Suite, M: Mode> Server<S, M> {
    /// Initialize a new server with a random secret key.
    ///
    /// The [`GenerateKeyPair`] method defined for the server in RFC 9497.
    ///
    /// [`GenerateKeyPair`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2-2
    pub fn random(rng: &mut impl RngCore) -> Self {
        let key = <S::Group as Group>::Scalar::random(rng);

        Server {
            key,
            payload: crate::mode::_From::_from(&key),
        }
    }

    /// Deterministically initialize a new server.
    ///
    /// The [`DeriveKeyPair`] method defined in RFC 9497.
    ///
    /// [`DeriveKeyPair`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2.1-2
    pub fn new(seed: [u8; 32], info: Input<'_>) -> Result<Self, InvalidSeed> {
        let mut counter = 0u8;
        let mut secret_key = <S::Group as Group>::Scalar::ZERO;
        while secret_key.is_zero().into() {
            let derive_input = [
                seed.as_slice(),
                &(info.as_ref().len() as u16).to_be_bytes(),
                info.as_ref(),
                &[counter],
            ];
            secret_key =
                S::hash_to_scalar(&derive_input, &context_string!(b"DeriveKeyPair"; <S, M>));
            counter = counter.checked_add(1).ok_or(InvalidSeed)?;
        }

        Ok(Server {
            key: secret_key,
            payload: crate::mode::_From::_from(&secret_key),
        })
    }
}

#[allow(private_bounds)]
impl<S, M> Server<S, M>
where
    S: Suite,
    M: Mode<ServerPayload<S::Group> = VerifyingKey<S::Group>>,
{
    /// The verifying key of the server.
    ///
    /// This is only accessible in modes that produce a proof, i.e., `mode::Verifiable` and
    /// `mode::Partial`.
    pub fn verifying_key(&self) -> VerifyingKey<S::Group> {
        self.payload
    }
}

impl<S: Suite> Server<S, mode::Base> {
    /// Evaluate the blinded element.
    ///
    /// Corresponds to the [`BlindEvaluate`] method defined for OPRFs in RFC 9497.
    ///
    /// [`BlindEvaluate`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-4
    pub fn evaluate(&self, Blind(blinded_element): Blind<S::Group>) -> Evaluated<S::Group>
where {
        let evaluated_element = blinded_element * self.key;
        Evaluated(evaluated_element)
    }
}

impl<S: Suite> Server<S, mode::Verifiable> {
    /// Evaluate the blinded element and prove the evaluation.
    ///
    /// The [`BlindEvaluate`] method defined for VOPRFs in RFC 9497. In contrast to the RFC, this
    /// method also returns the verifying key, since it is computed during the proof generation.
    ///
    /// [`BlindEvaluate`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
    pub fn evaluate_prove(
        &self,
        Blind(blinded_element): Blind<S::Group>,
        rng: &mut impl RngCore,
    ) -> (Evaluated<S::Group>, Proof<<S::Group as Group>::Scalar>) {
        let evaluated_element = Evaluated(blinded_element * self.key);
        let blinded_elements = [blinded_element];
        let evaluated_elements = [evaluated_element.0];
        let verifying_key = self.verifying_key();
        let proof = generate_proof::<1, S, mode::Verifiable>(
            self.key,
            S::Group::generator(),
            verifying_key.0,
            blinded_elements,
            evaluated_elements,
            rng,
        );

        (evaluated_element, proof)
    }
}

impl<S: Suite> Server<S, mode::Partial> {
    /// Evaluate the partially blinded element and prove the evaluation.
    ///
    /// Evaluates a partially blinded element, and generates a proof that the evaluation  was done
    /// with the server's private key and the shared information.
    ///
    /// The [`BlindEvaluate`] method defined for POPRFs in RFC 9497.
    ///
    /// [`BlindEvaluate`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
    #[allow(clippy::type_complexity)]
    pub fn evaluate_prove_partial(
        &self,
        blinded_element: Blind<S::Group>,
        info: Input<'_>,
        rng: &mut impl RngCore,
    ) -> Result<(Evaluated<S::Group>, Proof<<S::Group as Group>::Scalar>), UndefinedInverse> {
        let framed_info = [
            b"Info".as_slice(),
            &(info.as_ref().len() as u16).to_be_bytes(),
            info.as_ref(),
        ];
        let m = hash_to_scalar::<S, mode::Partial>(&framed_info);
        let t = self.key + m;

        let evaluated_element =
            Evaluated(blinded_element.0 * t.invert().into_option().ok_or(UndefinedInverse)?);

        let tweaked_key = S::Group::mul_by_generator(&t);
        let evaluated_elements = [evaluated_element.0];
        let blinded_elements = [blinded_element.0];
        let proof = generate_proof::<1, S, mode::Partial>(
            t,
            S::Group::generator(),
            tweaked_key,
            evaluated_elements,
            blinded_elements,
            rng,
        );

        Ok((evaluated_element, proof))
    }
}

/// Deterministic server creation error.
///
/// Creating a server with the provided `seed` and `info` results in an invalid private key.
/// This is practically impossible, and implies a broken `hash_to_scalar` or `PrimeField`
/// implementation.
///
/// Conforms with [Deterministic key generation] in RFC 9497.
///
/// [Deterministic key generation]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2.1
pub struct InvalidSeed;

/// Point inversion failed in partial oprf evaluation.
///
/// `evaluate_prove_partial` failed because the server's private key combined with the public
/// `info` results in a zero scalar. A RFC 9497 [states], this is practically impossible,
/// unless the public `info` provider is malicious and knows the server's private key.
///  
/// [states]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-6
pub struct UndefinedInverse;
