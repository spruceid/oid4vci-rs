use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::profiles::CredentialResponseProfile;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialResponse {
    credential: Value,
}

impl CredentialResponse {
    pub fn new(credential: Value) -> Self {
        Self { credential }
    }

    field_getters_setters![
        pub self [self] ["credential response value"] {
            set_credential -> credential[Value],
        }
    ];
}

impl CredentialResponseProfile for CredentialResponse {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::credential::Response;

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
                "credential": {
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                    ],
                    "id": "http://example.edu/credentials/3732",
                    "type": [
                        "VerifiableCredential",
                        "UniversityDegreeCredential"
                    ],
                    "issuer": "https://example.edu/issuers/565049",
                    "issuanceDate": "2010-01-01T00:00:00Z",
                    "credentialSubject": {
                        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                        "degree": {
                            "type": "BachelorDegree",
                            "name": "Bachelor of Science and Arts"
                        }
                    },
                    "proof": {
                        "type": "Ed25519Signature2020",
                        "created": "2022-02-25T14:58:43Z",
                        "verificationMethod": "https://example.edu/issuers/565049#key-1",
                        "proofPurpose": "assertionMethod",
                        "proofValue": "zeEdUoM7m9cY8ZyTpey83yBKeBcmcvbyrEQzJ19rD2UXArU2U1jPGoEt
                                       rRvGYppdiK37GU4NBeoPakxpWhAvsVSt"
                    }
                },
                "c_nonce": "fGFF7UkhLa",
                "c_nonce_expires_in": 86400
            }
        );

        let credential_response: Response<super::CredentialResponse> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_response).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }
}
