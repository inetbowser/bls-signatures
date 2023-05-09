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

pub use self::error::Error;
pub use self::key::{PrivateKey, PublicKey, Serialize};
pub use self::signature::{aggregate, hash, verify, verify_messages, Signature};

#[cfg(test)]
#[macro_use]
extern crate base64_serde;

#[cfg(feature = "serde")]
mod serde {
    use std::marker::PhantomData;

    use crate::*;

    impl_serialize!(
        PublicKey,
        PrivateKey,
        Signature,
        BlindSignature,
        BlindedMessage,
        BlindingFactor
    );

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
                        Ok(deserializer.deserialize_bytes(SerializeVisitor::<$x>(PhantomData))?)
                    }
                }
            )*
        };
    }

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
    }
}
