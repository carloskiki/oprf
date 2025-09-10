use digest::{Digest, Output};
use group::{Group, GroupEncoding, ff::Field};
use rand_core::RngCore;

use crate::{
    Blind, Evaluated, Mode, Proof, Suite, VerifyingKey, hash_to_group, hash_to_scalar,
    input::Input, mode, verify_proof,
};

/// Client of the OPRF protocol.
#[allow(private_bounds)]
pub struct Client<S: Suite, M: Mode> {
    blind: <S::Group as Group>::Scalar,
    digest: S::Hash,
    payload: M::ClientPayload<S::Group>,
}

impl<S: Suite> Client<S, mode::Base> {
    /// Blinds an input.
    ///
    /// The first step of the OPRF protocol for the client. The input is blinded using
    /// the provided random number generator.
    ///
    /// As specified in [RFC 9497 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2)
    pub fn blind(
        input: Input<'_>,
        rng: &mut impl RngCore,
    ) -> Result<(Self, Blind<S::Group>), InvalidInput> {
        let (blind, blinded_element, digest) = blind::<S, mode::Base, _>(input, rng)?;

        Ok((
            Client {
                blind,
                digest,
                payload: (),
            },
            blinded_element,
        ))
    }

    /// Finalize the protocol.
    ///
    /// Transforms the evaluated element into a pseudo-random output.
    ///
    /// Defined in [RFC 9497 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7)
    pub fn finalize(self, Evaluated(evaluated_element): Evaluated<S::Group>) -> Output<S::Hash> {
        let n = evaluated_element * self.blind.invert().expect("blind is non-zero");
        let unblinded_element = n.to_bytes();

        self.digest
            .chain_update((unblinded_element.as_ref().len() as u16).to_be_bytes())
            .chain_update(unblinded_element.as_ref())
            .chain_update("Finalize")
            .finalize()
    }
}

impl<S: Suite> Client<S, mode::Verifiable> {
    /// Blinds an input.
    ///
    /// The first step of the VOPRF protocol for the client. The input is blinded using
    /// the provided random number generator. The committed verifying key of the server
    /// is stored for later verification, conforming with the [security requirements] of the RFC.
    ///
    /// Specified in [RFC 9497 Section 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2)
    ///
    /// [security requirements]: https://www.rfc-editor.org/rfc/rfc9497.html#section-7.1-11
    pub fn blind(
        input: Input<'_>,
        verifying_key: crate::VerifyingKey<S::Group>,
        rng: &mut impl RngCore,
    ) -> Result<(Self, Blind<S::Group>), InvalidInput> {
        let (blind, blinded_element, digest) = blind::<S, mode::Verifiable, _>(input, rng)?;

        Ok((
            Client {
                blind,
                digest,
                payload: mode::VerifyingPayload {
                    verifying_key,
                    blinded_element,
                },
            },
            blinded_element,
        ))
    }
}

impl<S: Suite> Client<S, mode::Partial> {
    /// Blinds an input.
    ///
    /// The first step of the VOPRF protocol for the client. The input is blinded using
    /// the provided random number generator. The committed verifying key of the server
    /// is stored for later verification, conforming with the [security requirements] of the RFC.
    ///
    /// Specified in [RFC 9497 Section 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2)
    ///
    /// [security requirements]: https://www.rfc-editor.org/rfc/rfc9497.html#section-7.1-11
    pub fn blind(
        input: Input<'_>,
        info: Input<'_>,
        verifying_key: crate::VerifyingKey<S::Group>,
        rng: &mut impl RngCore,
    ) -> Result<(Self, Blind<S::Group>), InvalidInput> {
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

        let (blind, blinded_element, mut digest) = blind::<S, mode::Verifiable, _>(input, rng)?;
        digest.update((info.as_ref().len() as u16).to_be_bytes());
        digest.update(info.as_ref());

        Ok((
            Client {
                blind,
                digest,
                payload: mode::VerifyingPayload {
                    verifying_key: VerifyingKey(tweaked_key),
                    blinded_element,
                },
            },
            blinded_element,
        ))
    }
}

#[allow(private_bounds)]
impl<S, M> Client<S, M>
where
    S: Suite,
    M: Mode<ClientPayload<S::Group> = mode::VerifyingPayload<S::Group>>,
{
    /// Finalize the protocol.
    ///
    /// Transforms the evaluated element into a pseudo-random output.
    ///
    /// Defined in [RFC 9497 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7)
    pub fn finalize(
        self,
        Evaluated(evaluated_element): Evaluated<S::Group>,
        proof: Proof<<S::Group as Group>::Scalar>,
    ) -> Result<Output<S::Hash>, InvalidProof> {
        let evaluated_elements = [evaluated_element];
        let blinded_elements = [self.payload.blinded_element.0];
        let verifying_key = self.payload.verifying_key.0;
        if !verify_proof::<1, S, mode::Partial>(
            S::Group::generator(),
            verifying_key,
            evaluated_elements,
            blinded_elements,
            proof,
        ) {
            return Err(InvalidProof);
        }

        let n = evaluated_element * self.blind.invert().expect("blind is non-zero");
        let unblinded_element = n.to_bytes();

        Ok(self
            .digest
            .chain_update((unblinded_element.as_ref().len() as u16).to_be_bytes())
            .chain_update(unblinded_element.as_ref())
            .chain_update("Finalize")
            .finalize())
    }
}

#[allow(clippy::type_complexity)]
fn blind<S: Suite, M: Mode, R: RngCore>(
    input: Input<'_>,
    rng: &mut R,
) -> Result<(<S::Group as Group>::Scalar, Blind<S::Group>, S::Hash), InvalidInput> {
    let blind = <S::Group as Group>::Scalar::random(rng);
    let input_element: S::Group = hash_to_group::<S, mode::Base>(&[input.as_ref()]);
    let blinded_element = input_element * blind;
    if input_element.is_identity().into() {
        return Err(InvalidInput);
    }

    // This is performed here rather than in the [`finalize`] step of RFC 9497, so that we don't
    // require the `input` again in that step.
    //
    // [`finalize`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
    let mut digest = S::Hash::new();
    digest.update((input.as_ref().len() as u16).to_be_bytes());
    digest.update(input.as_ref());

    Ok((blind, Blind(blinded_element), digest))
}

/// The proof provided is invalid.
///
/// This is returned when proof verification fails.
///
/// Corresponds to [`VerifyError`] in RFC 9497.
///
/// [`VerifyError`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-5.3-2.2
pub struct InvalidProof;

/// The input provided is invalid.
///
/// This practically never happens. It is likely a sign that the `Rng` provided is compromised, or
/// that the `input` provided was crafted to cause a collision.
///
/// Corresponds to [`InvalidInputError`] in RFC 9497.
///
/// [`InvalidInputError`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-5.3-4.2
pub struct InvalidInput;
