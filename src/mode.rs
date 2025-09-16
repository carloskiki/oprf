//! The different modes in which the OPRF protocol can operate.
//!
//! These modes are defined as zero sized types to enforce correct use of
//! [`Client`][crate::client::Client] and [`Server`][crate::server::Server]. The mode is
//! provided as a type parameter to these structs, and the correct methods are exposed based
//! on it.

use group::Group;

use crate::{Blind, Input, VerifyingKey};

/// The basic (`OPRF`) mode of operation.
///
/// Allows a server and client to evaluate a pseudo-random function `F(x, k)` where the client
/// input `x` is not disclosed to the server, and the server key `k` is not disclosed to the
/// client. Only the client learns the output of the function.
///
/// Defined in [RFC 9497 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#name-oprf-protocol).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Base;

/// The verifiable (`VOPRF`) mode of operation.
///
/// In addition to the properties of the [`Base`] `OPRF` mode, the server provides a
/// [`Proof`][crate::Proof] of evaluation that the client can verify.
///
/// Defined in [RFC 9497 Section 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Verifiable;

/// The partially oblivious (`POPRF`) mode of operation.
///
/// In addition to the properties of the [`Verifiable`] (`VOPRF`) mode, a shared input between the
/// client and server is used.
///
/// Defined in [RFC 9497 Section 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#name-poprf-protocol).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Partial;

/// Helper trait for the different modes of OPRF operation.
pub(crate) trait Mode {
    /// The identifier for this mode.
    const IDENTIFIER: u8;

    /// Extra payload the client needs to run the protocol in this mode.
    type ClientPayload<'a, const N: usize, E>;
    type ServerPayload<E: Group>: for<'a> _From<&'a E::Scalar> + GetVerifyingKey<E>;
}

impl Mode for Base {
    const IDENTIFIER: u8 = 0x00;

    type ClientPayload<'a, const N: usize, E> = ();
    type ServerPayload<E: Group> = Empty;
}

impl Mode for Verifiable {
    const IDENTIFIER: u8 = 0x01;

    type ClientPayload<'a, const N: usize, E> = VerifyingPayload<N, E>;
    type ServerPayload<E: Group> = VerifyingKey<E>;
}

impl Mode for Partial {
    const IDENTIFIER: u8 = 0x02;

    type ClientPayload<'a, const N: usize, E> = PartialPayload<'a, N, E>;
    type ServerPayload<E: Group> = VerifyingKey<E>;
}

/// Helper `From` trait that does not have a blanket impl.
pub(crate) trait _From<E> {
    fn _from(e: E) -> Self;
}

/// Helper to try to get a verifying key from the server payload.
pub(crate) trait GetVerifyingKey<E> {
    fn get_verifying_key(&self) -> Option<VerifyingKey<E>>;
}

/// Extra payload the client needs to run the protocol when proof evaluation is needed.
pub(crate) struct VerifyingPayload<const N: usize, E> {
    /// The verifying_key of the server.
    pub verifying_key: VerifyingKey<E>,
    /// The blinded element.
    pub blinded_elements: [Blind<E>; N],
}

/// Extra payload the client needs to run the protocol when proof evaluation with shared info is
/// needed.
pub(crate) struct PartialPayload<'a, const N: usize, E> {
    /// The verifying_key of the server.
    pub verifying_key: VerifyingKey<E>,
    /// The blinded element.
    pub blinded_elements: [Blind<E>; N],
    /// The shared info.
    pub info: Input<'a>,
}

impl<E: Group> _From<&E::Scalar> for VerifyingKey<E> {
    fn _from(s: &E::Scalar) -> Self {
        VerifyingKey(E::mul_by_generator(s))
    }
}

impl<E: Group> GetVerifyingKey<E> for VerifyingKey<E> {
    fn get_verifying_key(&self) -> Option<VerifyingKey<E>> {
        Some(*self)
    }
}

/// Empty payload.
pub(crate) struct Empty;

impl<T> _From<&T> for Empty {
    fn _from(_: &T) -> Self {
        Empty
    }
}

impl<E> GetVerifyingKey<E> for Empty {
    fn get_verifying_key(&self) -> Option<VerifyingKey<E>> {
        None
    }
}
