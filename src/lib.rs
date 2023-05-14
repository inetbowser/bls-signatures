#[cfg(all(feature = "pairing", feature = "blst"))]
compile_error!("only pairing or blst can be enabled");

mod error;
mod key;
mod signature;

#[cfg(feature = "blind")]
mod blind;
#[cfg(feature = "blind")]
pub use self::blind::{BlindSignature, BlindedMessage, BlindingFactor};

#[cfg(feature = "musig")]
mod musig;
#[cfg(feature = "musig")]
pub use self::musig::KeyGroup;

pub use self::error::Error;
pub use self::key::{PrivateKey, PublicKey, Serialize};
pub use self::signature::{
    aggregate, custom_hash, signature_hash, verify, verify_messages, Signature,
};

#[cfg(feature = "pairing")]
pub use ::bls12_381;
#[cfg(feature = "pairing")]
pub use ::pairing_lib;

#[cfg(feature = "blst")]
pub use ::blstrs;
#[cfg(feature = "blst")]
pub use ::ff;
#[cfg(feature = "blst")]
pub use ::group;

#[cfg(test)]
#[macro_use]
extern crate base64_serde;

#[cfg(feature = "serde")]
mod serde {
    use std::marker::PhantomData;

    use crate::*;

    macro_rules! impl_serialize {
        ($( $x:ty ),*) => {
            $(
                impl ::serde::Serialize for $x {
                    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where
                        S: ::serde::Serializer,
                    {
                        serializer.serialize_bytes(self.as_bytes().as_ref())
                    }
                }

                impl<'de> ::serde::Deserialize<'de> for $x {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: ::serde::Deserializer<'de>
                    {
                        Ok(deserializer.deserialize_any(SerializeVisitor::<$x>(PhantomData))?)
                    }
                }
            )*
        };
    }

    impl_serialize!(
        PublicKey,
        PrivateKey,
        Signature,
        BlindSignature,
        BlindedMessage,
        BlindingFactor
    );

    struct SerializeVisitor<T: Serialize>(PhantomData<T>);

    impl<'de, T: Serialize> ::serde::de::Visitor<'de> for SerializeVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("bytes")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: ::serde::de::Error,
        {
            let obj = T::from_bytes(v).map_err(|err| E::custom(err))?;
            Ok(obj)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: ::serde::de::SeqAccess<'de>,
        {
            let mut bytes: Vec<u8> = vec![];

            if let Some(size) = seq.size_hint() {
                bytes.reserve_exact(size);
            }

            // Try to read sequence as array of bytes/u8s.
            while let Some(byte) = seq.next_element::<u8>()? {
                bytes.push(byte);
            }

            self.visit_bytes(&bytes)
        }
    }

    #[cfg(test)]
    mod tests {
        use rand_chacha::ChaChaRng;
        use rand_core::SeedableRng;

        use crate::{
            BlindSignature, BlindedMessage, BlindingFactor, PrivateKey, PublicKey, Signature,
        };

        macro_rules! serialize_and_deserialize {
            ($name:ident,$t:ty) => {{
                let serialized_data = serde_json::to_string(&$name).unwrap();
                let _: $t = serde_json::from_str(&serialized_data).unwrap();
            }};
        }

        #[test]
        fn test_serde() {
            let mut rng = ChaChaRng::seed_from_u64(1337);

            const MSG: &'static str = "Hello from serialize";

            let sk = PrivateKey::generate(&mut rng);
            let pk = sk.public_key();

            let sig = sk.sign(MSG);

            let (bmsg, bfac) = BlindedMessage::generate(MSG, &mut rng);
            let bsig = sk.blind_sign(&bmsg);

            serialize_and_deserialize!(sk, PrivateKey);
            serialize_and_deserialize!(pk, PublicKey);
            serialize_and_deserialize!(sig, Signature);
            serialize_and_deserialize!(bmsg, BlindedMessage);
            serialize_and_deserialize!(bfac, BlindingFactor);
            serialize_and_deserialize!(bsig, BlindSignature);
        }
    }
}
