use isomdl::definitions::IssuerSigned;
use serde::{Deserialize, Serialize};

use crate::profiles::CredentialResponseProfile;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialResponse;

impl CredentialResponseProfile for CredentialResponse {
    type Type = IsoIssuerSigned;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IsoIssuerSigned(#[serde(with = "base64_cbor")] IssuerSigned);

mod base64_cbor {
    use base64::{engine::general_purpose::URL_SAFE, Engine};
    use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Sized + Serialize, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        let v = match serde_cbor::to_vec(v) {
            Ok(v) => v,
            Err(e) => return Err(serde::ser::Error::custom(e)),
        };
        let b64 = URL_SAFE.encode(v);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, T: DeserializeOwned, D: Deserializer<'de>>(
        d: D,
    ) -> Result<T, D::Error> {
        let b64 = String::deserialize(d)?;
        match URL_SAFE.decode(b64) {
            Ok(v) => match serde_cbor::from_slice(&v) {
                Ok(v) => Ok(v),
                Err(e) => Err(serde::de::Error::custom(e)),
            },
            Err(e) => Err(serde::de::Error::custom(e)),
        }
    }
}
