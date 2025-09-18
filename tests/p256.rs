use digest::consts::U48;
use group::ff::PrimeField;
use oprf::mode::{Base, Partial, Verifiable};
use vector::parse_vectors;
use p256::ProjectivePoint;
use sha2::Sha256;

mod vector;

pub struct P256;

impl oprf::Suite for P256 {
    const IDENTIFIER: &'static [u8] = b"P256-SHA256";

    type Group = ProjectivePoint;

    type Hash = Sha256;

    fn hash_to_group(hash: &[&[u8]], domain: &[&[u8]]) -> Self::Group {
        hash2curve::hash_from_bytes::<p256::NistP256, hash2curve::ExpandMsgXmd<Sha256>>(
            hash, domain,
        )
        .expect("properly constructed")
    }

    fn hash_to_scalar(hash: &[&[u8]], domain: &[&[u8]]) -> <Self::Group as group::Group>::Scalar {
        hash2curve::hash_to_scalar::<p256::NistP256, hash2curve::ExpandMsgXmd<Sha256>, U48>(
            hash, domain,
        )
        .expect("properly constructed")
    }
}

#[test]
fn base() {
    parse_vectors! { <P256, Base>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf"
        [{
            Input = "00"
            Blind = "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d"
            EvaluationElement = "030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832"
            Output = "a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd" -
        },
        {
            Input = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "03cc1df781f1c2240a64d1c297b3f3d16262ef5d4cf102734882675c26231b0838"
            EvaluationElement = "03a0395fe3828f2476ffcd1f4fe540e5a8489322d398be3c4e5a869db7fcb7c52c"
            Output = "c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce" -
        }]
    }
    .test()
}

#[test]
fn verifiable() {
    parse_vectors! { <P256, Verifiable>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "ca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6"
        pkSm = "03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462"
        [{
            Input = "00"
            Blind = "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da"
            EvaluationElement = "0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2"
            Output = "0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1" -
            Proof = "e7c2b3c5c954c035949f1f74e6bce2ed539a3be267d1481e9ddb178533df4c2664f69d065c604a4fd953e100b856ad83804eb3845189babfa5a702090d6fc5fa"
            ProofRandomScalar = "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
        },
        {
            Input = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "03cd0f033e791c4d79dfa9c6ed750f2ac009ec46cd4195ca6fd3800d1e9b887dbd"
            EvaluationElement = "030d2985865c693bf7af47ba4d3a3813176576383d19aff003ef7b0784a0d83cf1"
            Output = "771e10dcd6bcd3664e23b8f2a710cfaaa8357747c4a8cbba03133967b5c24f18" -
            Proof = "2787d729c57e3d9512d3aa9e8708ad226bc48e0f1750b0767aaff73482c44b8d2873d74ec88aebd3504961acea16790a05c542d9fbff4fe269a77510db00abab"
            ProofRandomScalar = "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
        }]
    }.test();

    parse_vectors! { <P256, Verifiable>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "ca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6"
        pkSm = "03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462"
        [{
            Input = "00","5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364","f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
            BlindedElement = "02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da","03462e9ae64cae5b83ba98a6b360d942266389ac369b923eb3d557213b1922f8ab"
            EvaluationElement = "0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2","02bb24f4d838414aef052a8f044a6771230ca69c0a5677540fff738dd31bb69771"
            Output = "0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1","771e10dcd6bcd3664e23b8f2a710cfaaa8357747c4a8cbba03133967b5c24f18" -
            Proof = "bdcc351707d02a72ce49511c7db990566d29d6153ad6f8982fad2b435d6ce4d60da1e6b3fa740811bde34dd4fe0aa1b5fe6600d0440c9ddee95ea7fad7a60cf2"
            ProofRandomScalar = "350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963"
        }]
    }.test()
}

#[test]
fn partial() {
    parse_vectors! { <P256, Partial>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "6ad2173efa689ef2c27772566ad7ff6e2d59b3b196f00219451fb2c89ee4dae2"
        pkSm = "030d7ff077fddeec965db14b794f0cc1ba9019b04a2f4fcc1fa525dedf72e2a3e3"
        [{
            Input = "00"
            Blind = "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "031563e127099a8f61ed51eeede05d747a8da2be329b40ba1f0db0b2bd9dd4e2c0"
            EvaluationElement = "02c5e5300c2d9e6ba7f3f4ad60500ad93a0157e6288eb04b67e125db024a2c74d2"
            Output = "193a92520bd8fd1f37accb918040a57108daa110dc4f659abe212636d245c592" -
            Proof = "f8a33690b87736c854eadfcaab58a59b8d9c03b569110b6f31f8bf7577f3fbb85a8a0c38468ccde1ba942be501654adb106167c8eb178703ccb42bccffb9231a"
            ProofRandomScalar = "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
            Info = "7465737420696e666f"
        },
        {
            Input = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "021a440ace8ca667f261c10ac7686adc66a12be31e3520fca317643a1eee9dcd4d"
            EvaluationElement = "0208ca109cbae44f4774fc0bdd2783efdcb868cb4523d52196f700210e777c5de3"
            Output = "1e6d164cfd835d88a31401623549bf6b9b306628ef03a7962921d62bc5ffce8c" -
            Proof = "043a8fb7fc7fd31e35770cabda4753c5bf0ecc1e88c68d7d35a62bf2631e875af4613641be2d1875c31d1319d191c4bbc0d04875f4fd03c31d3d17dd8e069b69"
            ProofRandomScalar = "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
            Info = "7465737420696e666f"
        }]
    }.test();
    
    parse_vectors! { <P256, Partial>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "6ad2173efa689ef2c27772566ad7ff6e2d59b3b196f00219451fb2c89ee4dae2"
        pkSm = "030d7ff077fddeec965db14b794f0cc1ba9019b04a2f4fcc1fa525dedf72e2a3e3"
        [{
            Input = "00","5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364","f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
            BlindedElement = "031563e127099a8f61ed51eeede05d747a8da2be329b40ba1f0db0b2bd9dd4e2c0","03ca4ff41c12fadd7a0bc92cf856732b21df652e01a3abdf0fa8847da053db213c"
            EvaluationElement = "02c5e5300c2d9e6ba7f3f4ad60500ad93a0157e6288eb04b67e125db024a2c74d2","02f0b6bcd467343a8d8555a99dc2eed0215c71898c5edb77a3d97ddd0dbad478e8"
            Output = "193a92520bd8fd1f37accb918040a57108daa110dc4f659abe212636d245c592","1e6d164cfd835d88a31401623549bf6b9b306628ef03a7962921d62bc5ffce8c" -
            Proof = "8fbd85a32c13aba79db4b42e762c00687d6dbf9c8cb97b2a225645ccb00d9d7580b383c885cdfd07df448d55e06f50f6173405eee5506c0ed0851ff718d13e68"
            ProofRandomScalar = "350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963"
            Info = "7465737420696e666f"
        }]
    }.test()
}
