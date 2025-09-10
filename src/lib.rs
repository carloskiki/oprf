pub mod client;
mod input;
pub mod mode;
pub mod server;

use digest::Digest;
use group::{Group, GroupEncoding, ff::Field, prime::PrimeGroup};
use mode::Mode;
use rand_core::RngCore;

/// A ciphersuite for the OPRF protocol, [as defined in RFC 9497].
///
/// [as defined in RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497.html#name-ciphersuites
pub trait Suite {
    /// The identifier for this ciphersuite.
    const IDENTIFIER: &'static [u8];

    /// The prime-order group used in this ciphersuite.
    type Group: PrimeGroup + GroupEncoding;
    // TODO: Modeling `serialize` and `deserialize` with `GroupEncoding` is lazy and can easily
    // lead to implementation mistakes.
    // TODO: Make sure that `Group` and `Group::Scalar` encode to a size less than 2^16 bytes.

    /// The hash function used in this ciphersuite.
    type Hash: Digest;

    /// Hash to group routine used by this ciphersuite.
    fn hash_to_group(hash: &[&[u8]], domain: &[&[u8]]) -> Self::Group;

    /// Hash to scalar routine used by this ciphersuite.
    fn hash_to_scalar(hash: &[&[u8]], domain: &[&[u8]]) -> <Self::Group as Group>::Scalar;
}

/// A blinded element.
///
/// What the client sends to the server for evaluation, so that the server does not learn the
/// original input.
///
/// This is a simple wrapper to help prevent bewteen blinded, evaluated, and key elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Blind<E>(pub E);

/// An evaluated element.
///
/// What the server sends back to the client after evaluating the blinded element.
///
/// This is a simple wrapper to help prevent bewteen blinded, evaluated, and key elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Evaluated<E>(pub E);

/// The verifying key of the server.
///
/// This is a simple wrapper to help prevent bewteen blinded, evaluated, and key elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyingKey<E>(pub E);

/// Proof of evaluation.
///
/// A proof that the server evaluated the blinded element using its private key.
pub struct Proof<S> {
    c: S,
    s: S,
}

/// [`CreateContextString`] in RFC 9497, with a prefix.
///
/// [`CreateContextString`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.1-5
macro_rules! context_string {
    ($prefix:literal; <$suite:ty, $mode:ty>) => {
        [
            $prefix,
            b"OPRFV1-",
            &[<$mode>::IDENTIFIER],
            b"-",
            <$suite>::IDENTIFIER,
        ]
    };
}
pub(crate) use context_string;

/// Helper for hashing to a group with the appropriate domain.
fn hash_to_group<S: Suite, M: Mode>(hash: &[&[u8]]) -> S::Group {
    S::hash_to_group(hash, &context_string!(b"HashToGroup-"; <S, M>))
}

/// Helper for hashing to a group with the appropriate domain.
fn hash_to_scalar<S: Suite, M: Mode>(hash: &[&[u8]]) -> <S::Group as Group>::Scalar {
    S::hash_to_scalar(hash, &context_string!(b"HashToScalar-"; <S, M>))
}

/// Implementation of [`GenerateProof`] from RFC 9497.
///
/// [`GenerateProof`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-3
fn generate_proof<const N: usize, S: Suite, M: Mode>(
    k: <S::Group as Group>::Scalar,
    a: S::Group,
    b: S::Group,
    c: [S::Group; N],
    d: [S::Group; N],
    rng: &mut impl RngCore,
) -> Proof<<S::Group as Group>::Scalar> {
    let (m, z) = compute_composites_fast::<N, S, M>(k, b, c, d);

    let r = <S::Group as Group>::Scalar::random(rng);
    let t2 = a * r;
    let t3 = m * r;

    let bm = b.to_bytes();
    let a0 = m.to_bytes();
    let a1 = z.to_bytes();
    let a2 = t2.to_bytes();
    let a3 = t3.to_bytes();

    let challenge_transcript = [
        &(bm.as_ref().len() as u16).to_be_bytes(),
        bm.as_ref(),
        &(a0.as_ref().len() as u16).to_be_bytes(),
        a0.as_ref(),
        &(a1.as_ref().len() as u16).to_be_bytes(),
        a1.as_ref(),
        &(a2.as_ref().len() as u16).to_be_bytes(),
        a2.as_ref(),
        &(a3.as_ref().len() as u16).to_be_bytes(),
        a3.as_ref(),
        b"challenge",
    ];

    let c = hash_to_scalar::<S, M>(&challenge_transcript);
    let s = r - c * k;

    Proof { c, s }
}

// Implementation of [`ComputeCompositesFast`] from RFC 9497.
//
// [`ComputeCompositesFast`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-5
fn compute_composites_fast<const N: usize, S: Suite, M: Mode>(
    k: <S::Group as Group>::Scalar,
    b: S::Group,
    c: [S::Group; N],
    d: [S::Group; N],
) -> (S::Group, S::Group) {
    let bm = b.to_bytes();
    let seed_dst: [&[u8]; 5] = context_string!(b"Seed-"; <S, M>);
    let mut hasher = S::Hash::new();
    let seed_transcript = [
        &(bm.as_ref().len() as u16).to_be_bytes(),
        bm.as_ref(),
        &(seed_dst.iter().map(|s| s.len()).sum::<usize>() as u16).to_be_bytes(),
        seed_dst[0],
        seed_dst[1],
        seed_dst[2],
        seed_dst[3],
        seed_dst[4],
    ];
    seed_transcript.iter().for_each(|s| hasher.update(s));
    let seed = hasher.finalize();

    let mut m = S::Group::identity();
    for i in 0..N {
        let ci = c[i].to_bytes();
        let di = d[i].to_bytes();
        let composite_transcript = [
            &(seed.len() as u16).to_be_bytes(),
            seed.as_slice(),
            &(i as u16).to_be_bytes(),
            &(ci.as_ref().len() as u16).to_be_bytes(),
            ci.as_ref(),
            &(di.as_ref().len() as u16).to_be_bytes(),
            di.as_ref(),
            b"Composite",
        ];
        let di = hash_to_scalar::<S, M>(&composite_transcript);
        m = c[i] * di + m;
    }
    let z = m * k;
    (m, z)
}

/// Implementation of [`VerifyProof`] from RFC 9497.
///
/// [`VerifyProof`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.2-2
fn verify_proof<const N: usize, S: Suite, M: Mode>(
    a: S::Group,
    b: S::Group,
    c: [S::Group; N],
    d: [S::Group; N],
    proof: Proof<<S::Group as Group>::Scalar>,
) -> bool {
    let (m, z) = compute_composites::<N, S, M>(b, c, d);
    let c = proof.c;
    let s = proof.s;

    let t2 = a * s + b * c;
    let t3 = m * s + z * c;

    let bm = b.to_bytes();
    let a0 = m.to_bytes();
    let a1 = z.to_bytes();
    let a2 = t2.to_bytes();
    let a3 = t3.to_bytes();

    let challenge_transcript = [
        &(bm.as_ref().len() as u16).to_be_bytes(),
        bm.as_ref(),
        &(a0.as_ref().len() as u16).to_be_bytes(),
        a0.as_ref(),
        &(a1.as_ref().len() as u16).to_be_bytes(),
        a1.as_ref(),
        &(a2.as_ref().len() as u16).to_be_bytes(),
        a2.as_ref(),
        &(a3.as_ref().len() as u16).to_be_bytes(),
        a3.as_ref(),
        b"challenge",
    ];

    let expected_c = hash_to_scalar::<S, M>(&challenge_transcript);

    expected_c == c
}

/// Implementation of [`ComputeComposites`] from RFC 9497.
///
/// [`ComputeComposites`]: https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.2-4
fn compute_composites<const N: usize, S: Suite, M: Mode>(
    b: S::Group,
    c: [S::Group; N],
    d: [S::Group; N],
) -> (S::Group, S::Group) {
    let bm = b.to_bytes();
    let seed_dst: [&[u8]; 5] = context_string!(b"Seed-"; <S, M>);
    let mut hasher = S::Hash::new();
    let seed_transcript = [
        &(bm.as_ref().len() as u16).to_be_bytes(),
        bm.as_ref(),
        &(seed_dst.iter().map(|s| s.len()).sum::<usize>() as u16).to_be_bytes(),
        seed_dst[0],
        seed_dst[1],
        seed_dst[2],
        seed_dst[3],
        seed_dst[4],
    ];
    seed_transcript.iter().for_each(|s| hasher.update(s));
    let seed = hasher.finalize();

    let mut m = S::Group::identity();
    let mut z = S::Group::identity();
    for i in 0..N {
        let ci = c[i].to_bytes();
        let di = d[i].to_bytes();
        let composite_transcript = [
            &(seed.len() as u16).to_be_bytes(),
            seed.as_slice(),
            &(i as u16).to_be_bytes(),
            &(ci.as_ref().len() as u16).to_be_bytes(),
            ci.as_ref(),
            &(di.as_ref().len() as u16).to_be_bytes(),
            di.as_ref(),
            b"Composite",
        ];
        let di = hash_to_scalar::<S, M>(&composite_transcript);

        m = c[i] * di + m;
        z = d[i] * di + z;
    }

    (m, z)
}
