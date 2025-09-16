use group::ff::PrimeField;
use oprf::mode::{Base, Partial, Verifiable};
use std::num::NonZeroU16;

use curve25519_dalek::{RistrettoPoint, Scalar};
use digest::consts::U32;
use hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use sha2::Sha512;
use vector::parse_vectors;

mod vector;

struct Ristretto255;

impl oprf::Suite for Ristretto255 {
    type Group = RistrettoPoint;

    const IDENTIFIER: &'static [u8] = b"ristretto255-SHA512";

    type Hash = Sha512;

    fn hash_to_group(hash: &[&[u8]], domain: &[&[u8]]) -> Self::Group {
        let mut expander = <ExpandMsgXmd<Sha512> as ExpandMsg<U32>>::expand_message(
            hash,
            domain,
            NonZeroU16::new(64).expect("64 is non-zero"),
        )
        .expect("instantiation is valid");
        let mut uniform_bytes = [0u8; 64];
        expander
            .fill_bytes(&mut uniform_bytes)
            .expect("filling correct size");
        RistrettoPoint::from_uniform_bytes(&uniform_bytes)
    }

    fn hash_to_scalar(hash: &[&[u8]], domain: &[&[u8]]) -> <Self::Group as group::Group>::Scalar {
        let mut expander = <ExpandMsgXmd<Sha512> as ExpandMsg<U32>>::expand_message(
            hash,
            domain,
            NonZeroU16::new(64).expect("64 is non-zero"),
        )
        .expect("instantiation is valid");
        let mut uniform_bytes = [0u8; 64];
        expander
            .fill_bytes(&mut uniform_bytes)
            .expect("filling correct size");
        Scalar::from_bytes_mod_order_wide(&uniform_bytes)
    }
}

#[test]
fn base() {
    parse_vectors! { <Ristretto255, Base>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"
        [{
            Input = "00"
            Blind = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
            BlindedElement = "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"
            EvaluationElement = "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e"
            Output = "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6" -
        },
        {
            Input = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
            BlindedElement = "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418"
            EvaluationElement = "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25"
            Output = "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73" -
        }]
    }.test()
}

#[test]
fn verifiable() {
    parse_vectors! { <Ristretto255, Verifiable>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909"
        pkSm = "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e"
        [{
            Input = "00"
            Blind = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
            BlindedElement = "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"
            EvaluationElement = "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"
            Output = "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c" -
            Proof = "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d"
            ProofRandomScalar = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"
        },
        {
            Input = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
            BlindedElement = "cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c"
            EvaluationElement = "60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468"
            Output = "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6" -
            Proof = "401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02"
            ProofRandomScalar = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"
        }]
    }.test();

    parse_vectors! { <Ristretto255, Verifiable>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909"
        pkSm = "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e"
        [{
            Input = "00","5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706","222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"
            BlindedElement = "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945","90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654"
            EvaluationElement = "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e","cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a"
            Output = "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c","8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6" -
            Proof = "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08"
            ProofRandomScalar = "419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c"
        }]
    }.test();
}

#[test]
fn partial() {
    parse_vectors! { <Ristretto255, Partial>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07"
        pkSm = "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631"
        [{
            Input = "00"
            Blind = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
            BlindedElement = "c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715"
            EvaluationElement = "1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874"
            Output = "ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221" -
            Proof = "41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100de32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206"
            ProofRandomScalar = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"
            Info = "7465737420696e666f"
        },
        {
            Input = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
            BlindedElement = "f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d"
            EvaluationElement = "8c3c9d064c334c6991e99f286ea2301d1bde170b54003fb9c44c6d7bd6fc1540"
            Output = "7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507" -
            Proof = "4c39992d55ffba38232cdac88fe583af8a85441fefd7d1d4a8d0394cd1de77018bf135c174f20281b3341ab1f453fe72b0293a7398703384bed822bfdeec8908"
            ProofRandomScalar = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"
            Info = "7465737420696e666f"
        }]
    }.test();
    
    parse_vectors! { <Ristretto255, Partial>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07"
        pkSm = "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631"
        [{
            Input = "00","5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706","222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"
            BlindedElement = "c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715","423a01c072e06eb1cce96d23acce06e1ea64a609d7ec9e9023f3049f2d64e50c"
            EvaluationElement = "1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874","aa1f16e903841036e38075da8a46655c94fc92341887eb5819f46312adfc0504"
            Output = "ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221","7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507" -
            Proof = "43fdb53be399cbd3561186ae480320caa2b9f36cca0e5b160c4a677b8bbf4301b28f12c36aa8e11e5a7ef551da0781e863a6dc8c0b2bf5a149c9e00621f02006"
            ProofRandomScalar = "419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c"
            Info = "7465737420696e666f"
        }]
    }.test()
}
