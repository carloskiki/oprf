use p256::ProjectivePoint;
use sha2::Sha256;

pub struct P256;

impl oprf::Suite for P256 {
    const IDENTIFIER: &'static [u8] = b"P256-SHA256";

    type Group = ProjectivePoint;

    type Hash = Sha256;

    fn hash_to_group(hash: &[&[u8]], domain: &[&[u8]]) -> Self::Group {
        todo!()
    }

    fn hash_to_scalar(hash: &[&[u8]], domain: &[&[u8]]) -> <Self::Group as group::Group>::Scalar {
        todo!()
    }
}
