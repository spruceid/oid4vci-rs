use ssi::claims::{
    jws::{JwsSigner, JwsSignerInfo},
    SignatureError,
};

#[derive(Debug, Clone, Copy)]
pub struct NoSigner;

impl JwsSigner for NoSigner {
    async fn fetch_info(&self) -> Result<JwsSignerInfo, SignatureError> {
        Err(SignatureError::MissingSigner)
    }

    async fn sign_bytes(&self, _signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        Err(SignatureError::MissingSigner)
    }
}
