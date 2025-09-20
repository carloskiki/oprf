//! OPRF [`Client`] implementation.
//!
//! This module contains the [`Client`] type, and errors that the client may return.

use digest::{Digest, Output};
use group::{Group, GroupEncoding, ff::Field};
use rand_core::RngCore;

use crate::{
    Blinded, Evaluated, Input, Mode, Proof, Suite, VerifyingKey, hash_to_group, hash_to_scalar, mode,
    verify_proof,
};

/// Client of the OPRF protocol.
///
/// The client processes the [`Input`]s, blinds them, and later unblinds the [`Evaluated`]
/// elements by the [`Server`]. Depending on the [`mode`], it may also hold the [`VerifyingKey`]
/// of the [`Server`] to assert that the generated [`Proof`] of evaluation is correct.
///
/// This struct is highly generic which makes the `struct` definition look complex, but usage its
/// is straightforward. There are three distinct `blind` methods and three distinct `finalize` methods.
/// Calling [`Client::blind`] or [`Client::finalize`] will execute the correct method based on the
/// [`Mode`](mode) type parameter. In the documentation, these methods are distinguished by the
/// `impl Client<_, Mode>` blocks. The client supports batching of inputs by default, controlled by
/// the size of the input array provided to the `blind` method. If the client only needs to process
/// a single input, one can use an array of size one, e.g. `[input]`.
///
/// Here are quick links to the methods for the different modes: [`mode::Base`],
/// [`mode::Verifiable`], and [`mode::Partial`].
///
/// [`Server`]: crate::server::Server
/// [`mode::Base`]: #impl-Client<'a,+'b,+N,+S,+Base>
/// [`mode::Verifiable`]: #impl-Client<'a,+'b,+N,+S,+Verifiable>
/// [`mode::Partial`]: #impl-Client<'a,+'b,+N,+S,+Partial>
#[allow(private_bounds)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client<'a, 'b, const N: usize, S: Suite, M: Mode> {
    blinds: [<S::Group as Group>::Scalar; N],
    inputs: [Input<'a>; N],
    payload: M::ClientPayload<'b, N, S::Group>,
}

impl<const N: usize, S: Suite, M: Mode> zeroize::Zeroize for Client<'_, '_, N, S, M> {
    fn zeroize(&mut self) {
        self.blinds = core::array::from_fn(|_| <S::Group as Group>::Scalar::ZERO);
    }
}

#[allow(private_bounds)]
impl<'a, 'b, const N: usize, S: Suite, M: Mode> Client<'a, 'b, N, S, M> {
    /// `Mode` dependent implementation of the `blind` operation in `mode::Base`, so that the
    /// correct `context_string` is used in each mode. Reduces code duplication.
    ///
    /// Specified in [RFC 9497 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2)
    #[allow(clippy::type_complexity)]
    fn blind_impl(
        inputs: [Input<'a>; N],
        rng: &mut impl RngCore,
    ) -> Result<(Client<'a, 'b, N, S, mode::Base>, [Blinded<S::Group>; N]), InvalidInput> {
        let blinds = core::array::from_fn(|_| <S::Group as Group>::Scalar::random(rng));
        let mut error = None;
        let blinded_elements = core::array::from_fn(|i| {
            let input_element: S::Group = hash_to_group::<S, M>(&[inputs[i].as_ref()]);
            if input_element.is_identity().into() {
                error.replace(InvalidInput);
            }
            Blinded(input_element * blinds[i])
        });
        if let Some(InvalidInput) = error {
            return Err(InvalidInput);
        }

        Ok((
            Client {
                blinds,
                inputs,
                payload: (),
            },
            blinded_elements,
        ))
    }

    /// Code shared between all the `finealize` implementations, to reduce code duplication.
    ///
    /// Specified in [RFC 9497 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7)
    fn finalize_impl(self, evaluated_elements: [Evaluated<S::Group>; N]) -> [Output<S::Hash>; N] {
        let inverted_blinds = if N == 1 {
            self.blinds.map(|b| b.invert().expect("blind is non-zero"))
        } else {
            let mut blinds = self.blinds;
            let mut scratch = [<S::Group as Group>::Scalar::ONE; N];
            group::ff::BatchInverter::invert_with_external_scratch(&mut blinds, &mut scratch);
            blinds
        };

        core::array::from_fn(|i| {
            let n = evaluated_elements[i].0 * inverted_blinds[i];
            let unblinded_element = n.to_bytes();

            let mut digest = S::Hash::new();
            digest.update((self.inputs[i].as_ref().len() as u16).to_be_bytes());
            digest.update(self.inputs[i].as_ref());
            digest.update((unblinded_element.as_ref().len() as u16).to_be_bytes());
            digest.update(unblinded_element.as_ref());
            digest.update("Finalize");
            digest.finalize()
        })
    }
}

impl<'a, 'b, const N: usize, S: Suite> Client<'a, 'b, N, S, mode::Base> {
    /// Blinds an input.
    ///
    /// The first step of the OPRF protocol for the client. The input is blinded using
    /// the provided random number generator.
    ///
    /// Specified in [RFC 9497 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2).
    #[allow(clippy::type_complexity)]
    pub fn blind(
        inputs: [Input<'a>; N],
        rng: &mut impl RngCore,
    ) -> Result<(Self, [Blinded<S::Group>; N]), InvalidInput> {
        Self::blind_impl(inputs, rng)
    }

    /// Finalize the protocol.
    ///
    /// Transforms the [`Evaluated`] element into a pseudo-random output.
    ///
    /// Defined in [RFC 9497 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7)
    pub fn finalize(self, evaluated_elements: [Evaluated<S::Group>; N]) -> [Output<S::Hash>; N] {
        self.finalize_impl(evaluated_elements)
    }
}

impl<'a, 'b, const N: usize, S: Suite> Client<'a, 'b, N, S, mode::Verifiable> {
    /// Blinds an input.
    ///
    /// The first step of the VOPRF protocol for the client. The input is blinded using
    /// the provided random number generator. The committed verifying key of the server
    /// is stored for later verification, conforming with the [security requirements] of the RFC.
    ///
    /// Specified in [RFC 9497 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2)
    ///
    /// [security requirements]: https://www.rfc-editor.org/rfc/rfc9497.html#section-7.1-11
    #[allow(clippy::type_complexity)]
    pub fn blind(
        inputs: [Input<'a>; N],
        verifying_key: crate::VerifyingKey<S::Group>,
        rng: &mut impl RngCore,
    ) -> Result<(Self, [Blinded<S::Group>; N]), InvalidInput> {
        let (Client { blinds, inputs, .. }, blinded_elements) = Self::blind_impl(inputs, rng)?;
        Ok((
            Client {
                blinds,
                inputs,
                payload: mode::VerifyingPayload {
                    verifying_key,
                    blinded_elements,
                },
            },
            blinded_elements,
        ))
    }

    /// Finalize the protocol.
    ///
    /// Transforms the evaluated element into a pseudo-random output, and verifies the proof
    /// provided by the server.
    ///
    /// Defined in [RFC 9497 Section 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-5)
    pub fn finalize(
        self,
        evaluated_elements: [Evaluated<S::Group>; N],
        proof: Proof<<S::Group as Group>::Scalar>,
    ) -> Result<[Output<S::Hash>; N], InvalidProof> {
        let verifying_key = self.payload.verifying_key.0;
        if !verify_proof::<N, S, mode::Verifiable>(
            S::Group::generator(),
            verifying_key,
            self.payload.blinded_elements.map(|b| b.0),
            evaluated_elements.map(|e| e.0),
            proof,
        ) {
            return Err(InvalidProof);
        }

        Ok(self.finalize_impl(evaluated_elements))
    }
}

impl<'a, 'b, const N: usize, S: Suite> Client<'a, 'b, N, S, mode::Partial> {
    /// Blinds an input.
    ///
    /// The first step of the VOPRF protocol for the client. The input is blinded using
    /// the provided random number generator. The committed verifying key of the server
    /// is stored for later verification, conforming with the [security requirements] of the RFC.
    ///
    /// Specified in [RFC 9497 Section 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-2)
    ///
    /// [security requirements]: https://www.rfc-editor.org/rfc/rfc9497.html#section-7.1-11
    #[allow(clippy::type_complexity)]
    pub fn blind(
        inputs: [Input<'a>; N],
        info: Input<'b>,
        verifying_key: crate::VerifyingKey<S::Group>,
        rng: &mut impl RngCore,
    ) -> Result<(Self, [Blinded<S::Group>; N]), InvalidInput> {
        let framed_info = [
            b"Info".as_slice(),
            &(info.as_ref().len() as u16).to_be_bytes(),
            info.as_ref(),
        ];
        let m = hash_to_scalar::<S, mode::Partial>(&framed_info);
        let t = S::Group::mul_by_generator(&m);
        let tweaked_key = t + verifying_key.0;
        if tweaked_key.is_identity().into() {
            return Err(InvalidInput);
        }

        let (Client { blinds, inputs, .. }, blinded_elements) = Self::blind_impl(inputs, rng)?;

        Ok((
            Client {
                blinds,
                inputs,
                payload: mode::PartialPayload {
                    verifying_key: VerifyingKey(tweaked_key),
                    blinded_elements,
                    info,
                },
            },
            blinded_elements,
        ))
    }

    /// Finalize the protocol.
    ///
    /// Transforms the evaluated element into a pseudo-random output, and verifies the proof
    /// provided by the server.
    ///
    /// Defined in [RFC 9497 Section 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-8)
    pub fn finalize(
        self,
        evaluated_elements: [Evaluated<S::Group>; N],
        proof: Proof<<S::Group as Group>::Scalar>,
    ) -> Result<[Output<S::Hash>; N], InvalidProof> {
        let verifying_key = self.payload.verifying_key.0;
        if !verify_proof::<N, S, mode::Partial>(
            S::Group::generator(),
            verifying_key,
            evaluated_elements.map(|e| e.0),
            self.payload.blinded_elements.map(|b| b.0),
            proof,
        ) {
            return Err(InvalidProof);
        }

        let inverted_blinds = if N == 1 {
            self.blinds.map(|b| b.invert().expect("blind is non-zero"))
        } else {
            let mut blinds = self.blinds;
            let mut scratch = [<S::Group as Group>::Scalar::ONE; N];
            group::ff::BatchInverter::invert_with_external_scratch(&mut blinds, &mut scratch);
            blinds
        };

        Ok(core::array::from_fn(|i| {
            let n = evaluated_elements[i].0 * inverted_blinds[i];
            let unblinded_element = n.to_bytes();

            let mut digest = S::Hash::new();
            digest.update((self.inputs[i].as_ref().len() as u16).to_be_bytes());
            digest.update(self.inputs[i].as_ref());
            digest.update((self.payload.info.as_ref().len() as u16).to_be_bytes());
            digest.update(self.payload.info.as_ref());
            digest.update((unblinded_element.as_ref().len() as u16).to_be_bytes());
            digest.update(unblinded_element.as_ref());
            digest.update("Finalize");
            digest.finalize()
        }))
    }
}

/// The proof provided is invalid.
///
/// This is returned when proof verification fails. In other words, the proof fails to show that
/// the server used the correct key to evaluate the blinded element.
///
/// Corresponds to [`VerifyError`] in RFC 9497.
///
/// [`VerifyError`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-5.3-2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvalidProof;

impl core::fmt::Display for InvalidProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the proof provided is invalid")
    }
}

impl core::error::Error for InvalidProof {}

/// The input provided is invalid.
///
/// This practically never happens. It is roughly equivalent to finding a hash collision. This
/// error is likely a sign that the `RngCore` provided is compromised, or that the `input` was
/// crafted to cause a collision.
///
/// Corresponds to [`InvalidInputError`] in RFC 9497.
///
/// [`InvalidInputError`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-5.3-4.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvalidInput;

impl core::fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the input provided is invalid")
    }
}

impl core::error::Error for InvalidInput {}
