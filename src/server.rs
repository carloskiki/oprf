//! OPRF [`Server`] implementation.

use group::{Group, ff::Field};
use rand_core::RngCore;

use crate::{
    Blinded, Evaluated, Input, Proof, Suite, VerifyingKey, context_string, generate_proof,
    hash_to_scalar,
    mode::{self, GetVerifyingKey, Mode},
};

/// Server of the OPRF protocol.
///
/// The server holds a [`secret_key`], and evaluates blinded elements provided by the client.
/// Depending on the [`mode`], it may also generate a [`Proof`] that the evaluation was done correctly,
/// which the [`Client`] can verify using the server [`verifying_key`].
///
/// There are three distinct [`Server::evaluate`] methods, one for each [`mode`]:
/// - [`Server<_, Base>::evaluate`][Base]
/// - [`Server<_, Verifiable>::evaluate`][Verifiable]
/// - [`Server<_, Partial>::evaluate`][Partial]
///
/// The server supports batching of evaluations by default, as it accepts an array of [`Blinded`]
/// elements as input, and returns an array of [`Evaluated`] elements. If batching is not desired,
/// simply use an array of length 1.
///
/// [`secret_key`]: Server::secret_key
/// [`verifying_key`]: Server::verifying_key
/// [`Client`]: crate::client::Client
/// [Base]: #impl-Server<S,+Base>
/// [Verifiable]: #impl-Server<S,+Verifiable>
/// [Partial]: #impl-Server<S,+Partial>
#[allow(private_bounds)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server<S: Suite, M: Mode> {
    key: <S::Group as Group>::Scalar,
    payload: M::ServerPayload<S::Group>,
}

impl<S: Suite, M: Mode> zeroize::Zeroize for Server<S, M> {
    fn zeroize(&mut self) {
        self.key = <S::Group as Group>::Scalar::ZERO;
    }
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

    /// Initialize a new server from the provided secret key.
    ///
    /// This is not defined in RFC 9497 and not recommended, but is an obvious constructor that
    /// can be useful.
    pub fn from_secret_key(key: <S::Group as Group>::Scalar) -> Self {
        Server {
            key,
            payload: crate::mode::_From::_from(&key),
        }
    }

    /// Access the server's secret key.
    ///
    /// Be careful with it!
    pub fn secret_key(&self) -> &<S::Group as Group>::Scalar {
        &self.key
    }

    /// The verifying key of the server.
    ///
    /// This is only accessible in modes that produce a proof, i.e., `mode::Verifiable` and
    /// `mode::Partial`.
    pub fn verifying_key(&self) -> VerifyingKey<S::Group> {
        self.payload
            .get_verifying_key()
            .unwrap_or_else(|| VerifyingKey(S::Group::mul_by_generator(&self.key)))
    }
}

impl<S: Suite> Server<S, mode::Base> {
    /// Evaluate the blinded element.
    ///
    /// Corresponds to the [`BlindEvaluate`] method defined for OPRFs in RFC 9497.
    ///
    /// [`BlindEvaluate`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-4
    pub fn evaluate<const N: usize>(
        &self,
        blinded_elements: [Blinded<S::Group>; N],
    ) -> [Evaluated<S::Group>; N]
where {
        blinded_elements.map(|Blinded(blinded_element)| Evaluated(blinded_element * self.key))
    }
}

impl<S: Suite> Server<S, mode::Verifiable> {
    /// Evaluate the blinded element and prove the evaluation.
    ///
    /// The [`BlindEvaluate`] method defined for VOPRFs in RFC 9497.
    ///
    /// [`BlindEvaluate`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
    #[allow(clippy::type_complexity)]
    pub fn evaluate<const N: usize>(
        &self,
        blinded_elements: [Blinded<S::Group>; N],
        rng: &mut impl RngCore,
    ) -> ([Evaluated<S::Group>; N], Proof<<S::Group as Group>::Scalar>) {
        let evaluated_elements =
            blinded_elements.map(|Blinded(blinded_element)| Evaluated(blinded_element * self.key));
        let verifying_key = self.verifying_key();
        let proof = generate_proof::<N, S, mode::Verifiable>(
            self.key,
            S::Group::generator(),
            verifying_key.0,
            blinded_elements.map(|Blinded(b)| b),
            evaluated_elements.map(|Evaluated(e)| e),
            rng,
        );

        (evaluated_elements, proof)
    }
}

impl<S: Suite> Server<S, mode::Partial> {
    /// Evaluate the partially blinded element and prove the evaluation.
    ///
    /// The [`BlindEvaluate`] method defined for POPRFs in RFC 9497.
    ///
    /// [`BlindEvaluate`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
    #[allow(clippy::type_complexity)]
    pub fn evaluate<const N: usize>(
        &self,
        blinded_elements: [Blinded<S::Group>; N],
        info: Input<'_>,
        rng: &mut impl RngCore,
    ) -> Result<([Evaluated<S::Group>; N], Proof<<S::Group as Group>::Scalar>), UndefinedInverse>
    {
        let framed_info = [
            b"Info".as_slice(),
            &(info.as_ref().len() as u16).to_be_bytes(),
            info.as_ref(),
        ];
        let m = hash_to_scalar::<S, mode::Partial>(&framed_info);
        let t = self.key + m;
        let t_inv = t.invert().into_option().ok_or(UndefinedInverse)?;

        let evaluated_elements =
            blinded_elements.map(|Blinded(blinded_element)| Evaluated(blinded_element * t_inv));

        let tweaked_key = S::Group::mul_by_generator(&t);
        let proof = generate_proof::<N, S, mode::Partial>(
            t,
            S::Group::generator(),
            tweaked_key,
            evaluated_elements.map(|Evaluated(e)| e),
            blinded_elements.map(|Blinded(b)| b),
            rng,
        );

        Ok((evaluated_elements, proof))
    }
}

/// Deterministic server creation error.
///
/// Creating a server with the provided `seed` and `info` results in an invalid secret key.
/// This is practically impossible, and implies a broken `hash_to_scalar` or `PrimeField`
/// implementation.
///
/// Conforms with [Deterministic key generation] in RFC 9497.
///
/// [Deterministic key generation]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvalidSeed;

impl core::fmt::Display for InvalidSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the `seed` and `info` provided generate an invalid secret key"
        )
    }
}

impl core::error::Error for InvalidSeed {}

/// Point inversion failed in partial oprf evaluation.
///
/// `evaluate_prove_partial` failed because the server's secret key combined with the public
/// `info` results in a zero scalar. A [RFC 9497 states], this is practically impossible,
/// unless the public `info` provider is malicious and knows the server's secret key.
///  
/// [states]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-6
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UndefinedInverse;

impl core::fmt::Display for UndefinedInverse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "point inversion failed in partial OPRF evaluation")
    }
}

impl core::error::Error for UndefinedInverse {}
