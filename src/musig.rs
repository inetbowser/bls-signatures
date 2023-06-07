use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToField},
    G1Projective, G2Projective, Scalar,
};

#[cfg(feature = "multicore")]
use rayon::prelude::*;

use crate::{PublicKey, Serialize, Signature};

const KEYCOEFF_SUITE: &'static str = "BLS_MUSIG_KEYCOEFF_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub struct KeyGroup<'a> {
    keys: Box<[&'a PublicKey]>,
    agg_key: PublicKey,
}

impl<'a> KeyGroup<'a> {
    pub fn new(keys: &[&'a PublicKey]) -> Option<Self> {
        if keys.is_empty() {
            return None;
        }

        let agg_key = aggregate_keys(keys);
        Some(Self {
            keys: Box::from(keys),
            agg_key,
        })
    }

    pub fn aggregated_public_key(&self) -> &PublicKey {
        &self.agg_key
    }

    pub fn aggregate_partial_signatures(&self, partsigs: &[Signature]) -> Signature {
        let key_coeffs: Vec<Scalar> = self.keys.iter().map(|pk| compute_key_coeff(&self.keys, pk)).collect();
        aggregate_partsigs(key_coeffs, partsigs)
    }
}

#[cfg(feature = "pairing")]
fn compute_key_coeff(keys: &[&PublicKey], key: &PublicKey) -> Scalar {
    #[inline]
    fn hash_to_scalar(msg: &[u8]) -> Scalar {
        let mut hash_scalar = [Scalar::zero()];
        <Scalar as HashToField>::hash_to_field::<ExpandMsgXmd<sha2::Sha256>>(
            msg,
            KEYCOEFF_SUITE.as_bytes(),
            &mut hash_scalar,
        );
        hash_scalar[0]
    }

    let mut agg_bytes: Vec<u8> = vec![];
    agg_bytes.extend_from_slice(&key.as_bytes());
    for k in keys {
        agg_bytes.extend_from_slice(&k.as_bytes());
    }

    hash_to_scalar(&agg_bytes)
}

#[cfg(feature = "multicore")]
fn aggregate_keys(keys: &[&PublicKey]) -> PublicKey {
    let res = keys
        .into_par_iter()
        .fold(G1Projective::identity, |mut acc, key| {
            acc += key.0 * compute_key_coeff(keys, key);
            acc
        })
        .reduce(G1Projective::identity, |acc, val| acc + val);

    PublicKey(res)
}

#[cfg(feature = "multicore")]
fn aggregate_partsigs(key_coeffs: Vec<Scalar>, partsig: &[Signature]) -> Signature {
    assert!(key_coeffs.len() == partsig.len());

    let res = partsig
        .into_par_iter()
        .enumerate()
        .fold(G2Projective::identity, |mut acc, (i, sig)| {
            acc += sig.0 * key_coeffs[i];
            acc
        })
        .reduce(G2Projective::identity, |acc, val| acc + val);

    Signature(res.into())
}

#[cfg(not(feature = "multicore"))]
compile_error!("multicore agg_keys missing");

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::{musig::KeyGroup, PrivateKey};

    #[test]
    fn test_musig() {
        let mut rng = ChaChaRng::seed_from_u64(5269);

        const MSG: &'static str = "Hello world from all of us!";

        let sk1 = PrivateKey::generate(&mut rng);
        let pk1 = sk1.public_key();

        let sk2 = PrivateKey::generate(&mut rng);
        let pk2 = sk2.public_key();

        let sk3 = PrivateKey::generate(&mut rng);
        let pk3 = sk3.public_key();

        let group = KeyGroup::new(&[&pk1, &pk2, &pk3]).unwrap();

        let part1 = sk1.sign(MSG);
        let part2 = sk2.sign(MSG);
        let part3 = sk3.sign(MSG);

        let combined_sig = group.aggregate_partial_signatures(&[part1, part2, part3]);

        assert!(group.aggregated_public_key().verify(combined_sig, MSG));
    }
}
