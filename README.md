# OPRF

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Build Status][build-image]
![MIT licensed][license-image]
![Rust Version][rustc-image]

[crate-image]: https://img.shields.io/crates/v/oprf
[crate-link]: https://crates.io/crates/oprf
[docs-image]: https://docs.rs/oprf/badge.svg
[docs-link]: https://docs.rs/oprf/
[build-image]: https://github.com/carloskiki/oprf/actions/workflows/test.yml/badge.svg
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.89-blue.svg

Implementation of the Oblivious Pseudo Random Function (OPRF) protocol defined in
[RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html).

## What is an OPRF?

The introduction to RFC 9497 puts it best:

> A Pseudorandom Function (PRF) `F(k, x)` is an efficiently computable function taking a private key
`k` and a value `x` as input. This function is pseudorandom if the keyed function `K(_) = F(k, _)` is
indistinguishable from a randomly sampled function acting on the same domain and range as `K()`. An
Oblivious PRF (OPRF) is a two-party protocol between a server and a client, wherein the server
holds a PRF key `k` and the client holds some input `x`. The protocol allows both parties to cooperate
in computing `F(k, x)`, such that the client learns `F(k, x)` without learning anything about `k` and the
server does not learn anything about `x` or `F(k, x)`.

The scope of RFC 9497 and this crate covers three types of OPRFs:
- Base OPRF: The basic OPRF protocol, as described above.
- Verifiable OPRF (VOPRF): An extension of the base OPRF protocol where the server also provides a
    proof that it used the correct key `k` in the computation of `F(k, x)`, which the client can
    verify without learning `k`.
- Partial OPRF (POPRF): An extension to VOPRF where a shared input `y` between the client and
    server is also used in the computation: `F(k, x, y)`.

## TODO

- [x] Implement `Error` for error types.
- [x] Bound Group serialization to `u16::MAX`.
- [x] Proof serialization.
- [x] Batch implementation.
- [x] Test vectors.
- [x] CI
- [ ] Make all CI pass.
- [ ] Main crate documentation (100% coverage).
- [ ] Benchmarks.
- [ ] Publish.
