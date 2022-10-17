use ssi::{
    jwk::{Algorithm, JWK},
    jws::Header,
};

pub trait JOSEInterface {
    type Error;

    fn jwt_encode_sign(&self, bytes: &str) -> Result<String, Self::Error>;
    fn jwt_decode_verify(&self, jwt: &str) -> Result<(Header, Vec<u8>), Self::Error>;

    // TODO: replace by actual encryption
    fn jwe_encrypt(&self, bytes: &str) -> Result<String, Self::Error>;
    fn jwe_decrypt(&self, jwe: &str) -> Result<String, Self::Error>;

    fn get_public_key(&self) -> Result<JWK, Self::Error>;
}

pub struct SSI {
    pub jwk: JWK,
    pub alg: Algorithm,
}

impl SSI {
    pub fn new(jwk: JWK, alg: Algorithm) -> Self {
        SSI { jwk, alg }
    }
}

impl JOSEInterface for SSI {
    type Error = crate::OIDCError;

    fn jwt_encode_sign(&self, bytes: &str) -> Result<String, Self::Error> {
        ssi::jws::encode_sign(self.alg, bytes, &self.jwk).map_err(|e| e.into())
    }

    fn jwt_decode_verify(&self, jwt: &str) -> Result<(Header, Vec<u8>), Self::Error> {
        ssi::jws::decode_verify(jwt, &self.jwk).map_err(|e| e.into())
    }

    fn jwe_encrypt(&self, bytes: &str) -> Result<String, Self::Error> {
        // TODO: replace by actual encryption
        Ok(bytes.to_string())
    }

    fn jwe_decrypt(&self, jwe: &str) -> Result<String, Self::Error> {
        // TODO: replace by actual encryption
        Ok(jwe.to_string())
    }

    fn get_public_key(&self) -> Result<JWK, Self::Error> {
        unimplemented!()
    }
}
