use rand_core::CryptoRngCore;
use std::io;

#[cfg(feature = "pairing")]
use bls12_381::{Bls12, G1Affine, G2Affine, G2Projective, Scalar};
use ff::{PrimeField, PrimeFieldBits};

#[cfg(feature = "blst")]
use blstrs::{Bls12, G1Affine, G2Affine, G2Projective, Gt, MillerLoopResult, Scalar};
#[cfg(feature = "blst")]
use group::{prime::PrimeCurveAffine, Group};

use crate::{hash, signature::g2_from_slice, Error, PrivateKey, PublicKey, Serialize, Signature};

impl PrivateKey {
    /// Sign the given message blindly.
    /// Calculated by `signature = bmsg * sk`
    #[cfg(feature = "pairing")]
    pub fn blind_sign(&self, bmsg: &BlindedMessage) -> BlindSignature {
        let bsig = bmsg.0 * self.0;
        bsig.into()
    }
}

impl PublicKey {
    #[cfg(feature = "pairing")]
    pub fn blind_verify(&self, bsig: &BlindSignature, bmsg: &BlindedMessage) -> bool {
        use pairing_lib::Engine;

        <Bls12 as Engine>::pairing(&self.0.into(), &bmsg.0)
            == <Bls12 as Engine>::pairing(&G1Affine::generator(), &bsig.0)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct BlindedMessage(G2Affine);

impl BlindedMessage {
    #[cfg(feature = "pairing")]
    pub fn generate<R: CryptoRngCore, T: AsRef<[u8]>>(
        message: T,
        rng: &mut R,
    ) -> (BlindedMessage, BlindingFactor) {
        let mut bytes = [0u8; 64];
        rng.try_fill_bytes(&mut bytes)
            .expect("unable to produce secure randomness");

        let bfac = Scalar::from_bytes_wide(&bytes);

        let mut p = hash(message.as_ref());
        p *= bfac;

        (BlindedMessage(p.into()), BlindingFactor(bfac))
    }
}

impl From<G2Projective> for BlindedMessage {
    fn from(val: G2Projective) -> Self {
        BlindedMessage(val.into())
    }
}
impl From<BlindedMessage> for G2Projective {
    fn from(val: BlindedMessage) -> Self {
        val.0.into()
    }
}

impl From<G2Affine> for BlindedMessage {
    fn from(val: G2Affine) -> Self {
        BlindedMessage(val)
    }
}

impl From<BlindedMessage> for G2Affine {
    fn from(val: BlindedMessage) -> Self {
        val.0
    }
}

impl Serialize for BlindedMessage {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        dest.write_all(&self.0.to_compressed())?;

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let g2 = g2_from_slice(raw)?;
        Ok(g2.into())
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct BlindingFactor(Scalar);

impl From<Scalar> for BlindingFactor {
    fn from(value: Scalar) -> Self {
        Self(value)
    }
}

impl From<BlindingFactor> for Scalar {
    fn from(value: BlindingFactor) -> Self {
        value.0
    }
}

impl Serialize for BlindingFactor {
    fn write_bytes(&self, dest: &mut impl std::io::Write) -> std::io::Result<()> {
        for digit in &self.0.to_le_bits().data {
            dest.write_all(&digit.to_le_bytes())?;
        }

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        const FR_SIZE: usize = (Scalar::NUM_BITS as usize + 8 - 1) / 8;
        if raw.len() != FR_SIZE {
            return Err(Error::SizeMismatch);
        }

        let mut res = [0u8; FR_SIZE];
        res.copy_from_slice(&raw[..FR_SIZE]);

        // TODO: once zero keys are rejected, insert check for zero.

        Scalar::from_repr_vartime(res)
            .map(Into::into)
            .ok_or(Error::FieldDecode)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct BlindSignature(G2Affine);

impl BlindSignature {
    /// Unblind the signature.
    #[cfg(feature = "pairing")]
    pub fn unblind(&self, bfac: &BlindingFactor) -> Signature {
        let mut p: G2Projective = self.0.into();
        p *= bfac.0.invert().unwrap();
        Signature::from(p)
    }
}

impl From<G2Projective> for BlindSignature {
    fn from(val: G2Projective) -> Self {
        BlindSignature(val.into())
    }
}
impl From<BlindSignature> for G2Projective {
    fn from(val: BlindSignature) -> Self {
        val.0.into()
    }
}

impl From<G2Affine> for BlindSignature {
    fn from(val: G2Affine) -> Self {
        BlindSignature(val)
    }
}

impl From<BlindSignature> for G2Affine {
    fn from(val: BlindSignature) -> Self {
        val.0
    }
}

impl Serialize for BlindSignature {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        dest.write_all(&self.0.to_compressed())?;

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let g2 = g2_from_slice(raw)?;
        Ok(g2.into())
    }
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use crate::PrivateKey;

    use super::BlindedMessage;

    #[test]
    fn test_blind_sig() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1337);
        let msg = "Gello, world!";

        let sk = PrivateKey::generate(&mut rng);
        let pk = sk.public_key();

        let (bmsg, bfac) = BlindedMessage::generate(msg, &mut rng);
        let bsig = sk.blind_sign(&bmsg);

        assert!(pk.blind_verify(&bsig, &bmsg));

        let sig = bsig.unblind(&bfac);
        assert!(pk.verify(sig, msg));
    }
}
