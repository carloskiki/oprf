//! The different modes in which the OPRF protocol can operate.
//!
//! These modes are defined as zero sized types to enforce correct use of
//! [`Client`][crate::client::Client] and [`Server`][crate::server::Server]. The mode is
//! provided as a type parameter to these structs, and the correct methods are exposed based
//! on it.

use group::{ff::PrimeField, prime::PrimeGroup};

use crate::{Blind, VerifyingKey};

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
    type ClientPayload<E>;
    type ServerPayload<E: PrimeGroup>: for<'a> _From<&'a E::Scalar>;
}

impl Mode for Base {
    const IDENTIFIER: u8 = 0x00;

    type ClientPayload<E> = ();
    type ServerPayload<E: PrimeGroup> = Empty;
}

impl Mode for Verifiable {
    const IDENTIFIER: u8 = 0x01;

    type ClientPayload<E> = VerifyingPayload<E>;
    type ServerPayload<E: PrimeGroup> = VerifyingKey<E>;
}

impl Mode for Partial {
    const IDENTIFIER: u8 = 0x02;

    type ClientPayload<E> = VerifyingPayload<E>;
    type ServerPayload<E: PrimeGroup> = VerifyingKey<E>;
}

/// Helper `From` trait that does not have a blanket impl.
pub(crate) trait _From<E> {
    fn _from(e: E) -> Self;
}

/// Extra payload the server needs to run the protocol when proof evaluation is needed.
pub(crate) struct VerifyingPayload<E> {
    /// The verifying_key of the server.
    pub verifying_key: VerifyingKey<E>,
    /// The blinded element evaluated by the server.
    pub blinded_element: Blind<E>,
}

/// Empty payload.
pub(crate) struct Empty;

impl<T> _From<&T> for Empty {
    fn _from(_: &T) -> Self {
        Empty
    }
}

impl<S: PrimeField> From<S> for Empty {
    fn from(_: S) -> Self {
        Empty
    }
}

impl<E: PrimeGroup> _From<&E::Scalar> for VerifyingKey<E> {
    fn _from(s: &E::Scalar) -> Self {
        VerifyingKey(E::mul_by_generator(s))
    }
}
