#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::response::ImmediateCredentialResponse;

    #[test]
    fn jwt_roundtrip() {
        let expected_json = json!(
            {
                "credentials": [
                    {
                        "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzU2NTA0OSIsImlzc3VhbmNlRGF0ZSI6IjIwMTAtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19LCJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvNTY1MDQ5IiwibmJmIjoxMjYyMzA0MDAwLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9.z5vgMTK1nfizNCg5N-niCOL3WUIAL7nXy-nGhDZYO_-PNGeE-0djCpWAMH8fD8eWSID5PfkPBYkx_dfLJnQ7NA"
                    }
                ]
            }
        );

        let credential_response: ImmediateCredentialResponse =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_response).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }

    #[test]
    fn ldp_roundtrip() {
        let expected_json = json!(
            {
                "credentials": [
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
                        }
                    }
                ]
            }
        );

        let credential_response: ImmediateCredentialResponse =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_response).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }
}
