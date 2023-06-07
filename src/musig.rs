use bls12_381::{
    G1Projective, G1Affine, Scalar, pairing, G2Affine,
    hash_to_curve::{ExpandMsgXmd, HashToField},
};

#[cfg(feature = "multicore")]
use rayon::prelude::*;

use crate::{signature_hash, PrivateKey, PublicKey, Serialize, Signature};

const KEYCOEFF_SUITE: &'static str = "BLS_MUSIG_KEYCOEFF_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub struct KeyGroup {
    keys: Box<[PublicKey]>,
    agg_key: PublicKey,
}

impl KeyGroup {
    pub fn new(keys: &[PublicKey]) -> Option<Self> {
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

    pub fn sign_partial<T: AsRef<[u8]>>(&self, sk: &PrivateKey, message: T) -> Signature {
        let coeff = compute_key_coeff(&self.keys, &sk.public_key());
        let mut p = signature_hash(message.as_ref());
        p *= sk.0 * coeff;

        p.into()
    }

    pub fn verify_partial<T: AsRef<[u8]>>(&self, idx: usize, sig: Signature, message: T) -> bool {
        let coeff = compute_key_coeff(&self.keys, &self.keys[idx]);
        let key_with_coeff: G1Affine = (self.keys[idx].0 * coeff).into();
        let hash: G2Affine = signature_hash(message.as_ref()).into();

        pairing(&G1Affine::generator(), &sig.0) == pairing(&key_with_coeff, &hash)
    }
}

#[cfg(feature = "pairing")]
fn compute_key_coeff(keys: &[PublicKey], key: &PublicKey) -> Scalar {
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
fn aggregate_keys(keys: &[PublicKey]) -> PublicKey {
    let res = keys
        .into_par_iter()
        .fold(G1Projective::identity, |mut acc, key| {
            acc += key.0 * compute_key_coeff(keys, key);
            acc
        })
        .reduce(G1Projective::identity, |acc, val| acc + val);

    PublicKey(res)
}

#[cfg(not(feature = "multicore"))]
compile_error!("multicore agg_keys missing");

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::{aggregate, musig::KeyGroup, PrivateKey};

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

        let group = KeyGroup::new(&[pk1, pk2, pk3]).unwrap();

        let part1 = group.sign_partial(&sk1, MSG);
        let part2 = group.sign_partial(&sk2, MSG);
        let part3 = group.sign_partial(&sk3, MSG);

        assert!(group.verify_partial(0, part1.clone(), MSG));
        assert!(group.verify_partial(1, part2.clone(), MSG));
        assert!(group.verify_partial(2, part3.clone(), MSG));

        let combined_sig = aggregate(&[part1, part2, part3]).unwrap();

        assert!(group.aggregated_public_key().verify(combined_sig, MSG));
    }
}
