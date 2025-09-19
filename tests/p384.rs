use digest::consts::U72;
use group::ff::PrimeField;
use oprf::mode::{Base, Partial, Verifiable};
use p384::ProjectivePoint;
use sha2::Sha384;
use vector::parse_vectors;

mod vector;

pub struct P384;

impl oprf::Suite for P384 {
    const IDENTIFIER: &'static [u8] = b"P384-SHA384";

    type Group = ProjectivePoint;

    type Hash = Sha384;

    fn hash_to_group(hash: &[&[u8]], domain: &[&[u8]]) -> Self::Group {
        hash2curve::hash_from_bytes::<p384::NistP384, hash2curve::ExpandMsgXmd<Sha384>>(
            hash, domain,
        )
        .expect("properly constructed")
    }

    fn hash_to_scalar(hash: &[&[u8]], domain: &[&[u8]]) -> <Self::Group as group::Group>::Scalar {
        hash2curve::hash_to_scalar::<p384::NistP384, hash2curve::ExpandMsgXmd<Sha384>, U72>(
            hash, domain,
        )
        .expect("properly constructed")
    }
}

#[test]
fn base() {
    parse_vectors! { <P384, Base>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "dfe7ddc41a4646901184f2b432616c8ba6d452f9bcd0c4f75a5150ef2b2ed02ef40b8b92f60ae591bcabd72a6518f188"
        [{
            Input = "00"
            Blind = "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "02a36bc90e6db34096346eaf8b7bc40ee1113582155ad3797003ce614c835a874343701d3f2debbd80d97cbe45de6e5f1f"
            EvaluationElement = "03af2a4fc94770d7a7bf3187ca9cc4faf3732049eded2442ee50fbddda58b70ae2999366f72498cdbc43e6f2fc184afe30"
            Output = "ed84ad3f31a552f0456e58935fcc0a3039db42e7f356dcb32aa6d487b6b815a07d5813641fb1398c03ddab5763874357" -
        }, {
            Input = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "02def6f418e3484f67a124a2ce1bfb19de7a4af568ede6a1ebb2733882510ddd43d05f2b1ab5187936a55e50a847a8b900"
            EvaluationElement = "034e9b9a2960b536f2ef47d8608b21597ba400d5abfa1825fd21c36b75f927f396bf3716c96129d1fa4a77fa1d479c8d7b"
            Output = "dd4f29da869ab9355d60617b60da0991e22aaab243a3460601e48b075859d1c526d36597326f1b985778f781a1682e75" -
        }]
    }.test()
}

#[test]
fn verifiable() {
    parse_vectors! { <P384, Verifiable>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "051646b9e6e7a71ae27c1e1d0b87b4381db6d3595eeeb1adb41579adbf992f4278f9016eafc944edaa2b43183581779d"
        pkSm = "031d689686c611991b55f1a1d8f4305ccd6cb719446f660a30db61b7aa87b46acf59b7c0d4a9077b3da21c25dd482229a0"
        [{
            Input = "00"
            Blind = "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "02d338c05cbecb82de13d6700f09cb61190543a7b7e2c6cd4fca56887e564ea82653b27fdad383995ea6d02cf26d0e24d9"
            EvaluationElement = "02a7bba589b3e8672aa19e8fd258de2e6aae20101c8d761246de97a6b5ee9cf105febce4327a326255a3c604f63f600ef6"
            Output = "3333230886b562ffb8329a8be08fea8025755372817ec969d114d1203d026b4a622beab60220bf19078bca35a529b35c" -
            Proof = "bfc6cf3859127f5fe25548859856d6b7fa1c7459f0ba5712a806fc091a3000c42d8ba34ff45f32a52e40533efd2a03bc87f3bf4f9f58028297ccb9ccb18ae7182bcd1ef239df77e3be65ef147f3acf8bc9cbfc5524b702263414f043e3b7ca2e"
            ProofRandomScalar = "803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
        }, {
            Input = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "02f27469e059886f221be5f2cca03d2bdc61e55221721c3b3e56fc012e36d31ae5f8dc058109591556a6dbd3a8c69c433b"
            EvaluationElement = "03f16f903947035400e96b7f531a38d4a07ac89a80f89d86a1bf089c525a92c7f4733729ca30c56ce78b1ab4f7d92db8b4"
            Output = "b91c70ea3d4d62ba922eb8a7d03809a441e1c3c7af915cbc2226f485213e895942cd0f8580e6d99f82221e66c40d274f" -
            Proof = "d005d6daaad7571414c1e0c75f7e57f2113ca9f4604e84bc90f9be52da896fff3bee496dcde2a578ae9df315032585f801fb21c6080ac05672b291e575a40295b306d967717b28e08fcc8ad1cab47845d16af73b3e643ddcc191208e71c64630"
            ProofRandomScalar = "803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
        }]
    }.test();

    parse_vectors! { <P384, Verifiable>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "051646b9e6e7a71ae27c1e1d0b87b4381db6d3595eeeb1adb41579adbf992f4278f9016eafc944edaa2b43183581779d"
        pkSm = "031d689686c611991b55f1a1d8f4305ccd6cb719446f660a30db61b7aa87b46acf59b7c0d4a9077b3da21c25dd482229a0"
        [{
            Input = "00","5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364","803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
            BlindedElement = "02d338c05cbecb82de13d6700f09cb61190543a7b7e2c6cd4fca56887e564ea82653b27fdad383995ea6d02cf26d0e24d9","02fa02470d7f151018b41e82223c32fad824de6ad4b5ce9f8e9f98083c9a726de9a1fc39d7a0cb6f4f188dd9cea01474cd"
            EvaluationElement = "02a7bba589b3e8672aa19e8fd258de2e6aae20101c8d761246de97a6b5ee9cf105febce4327a326255a3c604f63f600ef6","028e9e115625ff4c2f07bf87ce3fd73fc77994a7a0c1df03d2a630a3d845930e2e63a165b114d98fe34e61b68d23c0b50a"
            Output = "3333230886b562ffb8329a8be08fea8025755372817ec969d114d1203d026b4a622beab60220bf19078bca35a529b35c","b91c70ea3d4d62ba922eb8a7d03809a441e1c3c7af915cbc2226f485213e895942cd0f8580e6d99f82221e66c40d274f" -
            Proof = "6d8dcbd2fc95550a02211fb78afd013933f307d21e7d855b0b1ed0af78076d8137ad8b0a1bfa05676d325249c1dbb9a52bd81b1c2b7b0efc77cf7b278e1c947f6283f1d4c513053fc0ad19e026fb0c30654b53d9cea4b87b037271b5d2e2d0ea"
            ProofRandomScalar = "a097e722ed2427de86966910acba9f5c350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963"
        }]
    }.test()
}

#[test]
fn partial() {
    parse_vectors! { <P384, Partial>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "5b2690d6954b8fbb159f19935d64133f12770c00b68422559c65431942d721ff79d47d7a75906c30b7818ec0f38b7fb2"
        pkSm = "02f00f0f1de81e5d6cf18140d4926ffdc9b1898c48dc49657ae36eb1e45deb8b951aaf1f10c82d2eaa6d02aafa3f10d2b6"
        [{
            Input = "00"
            Blind = "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "03859b36b95e6564faa85cd3801175eda2949707f6aa0640ad093cbf8ad2f58e762f08b56b2a1b42a64953aaf49cbf1ae3"
            EvaluationElement = "0220710e2e00306453f5b4f574cb6a512453f35c45080d09373e190c19ce5b185914fbf36582d7e0754bb7c8b683205b91"
            Output = "0188653cfec38119a6c7dd7948b0f0720460b4310e40824e048bf82a16527303ed449a08caf84272c3bbc972ede797df" -
            Proof = "82a17ef41c8b57f1e3122311b4d5cd39a63df0f67443ef18d961f9b659c1601ced8d3c64b294f604319ca80230380d437a49c7af0d620e22116669c008ebb767d90283d573b49cdb49e3725889620924c2c4b047a2a6225a3ba27e640ebddd33"
            ProofRandomScalar = "803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
            Info = "7465737420696e666f"
        }, {
            Input = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
            BlindedElement = "03f7efcb4aaf000263369d8a0621cb96b81b3206e99876de2a00699ed4c45acf3969cd6e2319215395955d3f8d8cc1c712"
            EvaluationElement = "034993c818369927e74b77c400376fd1ae29b6ac6c6ddb776cf10e4fbc487826531b3cf0b7c8ca4d92c7af90c9def85ce6"
            Output = "ff2a527a21cc43b251a567382677f078c6e356336aec069dea8ba36995343ca3b33bb5d6cf15be4d31a7e6d75b30d3f5" -
            Proof = "693471b5dff0cd6a5c00ea34d7bf127b2795164e3bdb5f39a1e5edfbd13e443bc516061cd5b8449a473c2ceeccada9f3e5b57302e3d7bc5e28d38d6e3a3056e1e73b6cc030f5180f8a1ffa45aa923ee66d2ad0a07b500f2acc7fb99b5506465c"
            ProofRandomScalar = "803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
            Info = "7465737420696e666f"
        }]
    }.test();

    parse_vectors! { <P384, Partial>:
        Seed = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
        KeyInfo = "74657374206b6579"
        skSm = "5b2690d6954b8fbb159f19935d64133f12770c00b68422559c65431942d721ff79d47d7a75906c30b7818ec0f38b7fb2"
        pkSm = "02f00f0f1de81e5d6cf18140d4926ffdc9b1898c48dc49657ae36eb1e45deb8b951aaf1f10c82d2eaa6d02aafa3f10d2b6"
        [{
            Input = "00","5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            Blind = "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364","803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"
            BlindedElement = "03859b36b95e6564faa85cd3801175eda2949707f6aa0640ad093cbf8ad2f58e762f08b56b2a1b42a64953aaf49cbf1ae3","021a65d618d645f1a20bc33b06deaa7e73d6d634c8a56a3d02b53a732b69a5c53c5a207ea33d5afdcde9a22d59726bce51"
            EvaluationElement = "0220710e2e00306453f5b4f574cb6a512453f35c45080d09373e190c19ce5b185914fbf36582d7e0754bb7c8b683205b91","02017657b315ec65ef861505e596c8645d94685dd7602cdd092a8f1c1c0194a5d0485fe47d071d972ab514370174cc23f5"
            Output = "0188653cfec38119a6c7dd7948b0f0720460b4310e40824e048bf82a16527303ed449a08caf84272c3bbc972ede797df","ff2a527a21cc43b251a567382677f078c6e356336aec069dea8ba36995343ca3b33bb5d6cf15be4d31a7e6d75b30d3f5" -
            Proof = "4a0b2fe96d5b2a046a0447fe079b77859ef11a39a3520d6ff7c626aad9b473b724fb0cf188974ec961710a62162a83e97e0baa9eeada73397032d928b3e97b1ea92ad9458208302be3681b8ba78bcc17745bac00f84e0fdc98a6a8cba009c080"
            ProofRandomScalar = "a097e722ed2427de86966910acba9f5c350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963"
            Info = "7465737420696e666f"
        }]
    }.test()
}
