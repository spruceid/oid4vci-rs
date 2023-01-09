use ssi::{
    jwk::{Algorithm, JWK},
    jws::Header,
};

pub trait JOSEInterface {
    type Error;

    fn jwt_encode_sign(&self, bytes: &str) -> Result<String, Self::Error>;
    fn jwt_decode_verify(&self, jwt: &str) -> Result<(Header, Vec<u8>), Self::Error>;

    fn jwe_encrypt(&self, bytes: &str) -> Result<String, Self::Error>;
    fn jwe_decrypt(&self, jwe: &str) -> Result<String, Self::Error>;

    fn get_public_key(&self) -> Result<JWK, Self::Error>;
}

#[derive(Clone)]
pub struct SSI {
    pub jwk: JWK,
    pub alg: Algorithm,

    pub password: String,
}

impl SSI {
    pub fn new(jwk: JWK, alg: Algorithm, password: &str) -> Self {
        SSI {
            jwk,
            alg,
            password: password.to_string(),
        }
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
        use josekit::{
            jwe::{JweHeader, PBES2_HS512_A256KW},
            jwt::{self, JwtPayload},
        };

        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A256GCM");

        let mut payload = JwtPayload::new();
        payload.set_subject(bytes);

        let encrypter = PBES2_HS512_A256KW.encrypter_from_bytes(self.password.as_bytes())?;
        let jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter)?;

        Ok(jwt)
    }

    fn jwe_decrypt(&self, jwe: &str) -> Result<String, Self::Error> {
        use josekit::{
            jwe::{JweHeader, PBES2_HS512_A256KW},
            jwt,
        };

        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A256GCM");

        let decrypter = PBES2_HS512_A256KW.decrypter_from_bytes(self.password.as_bytes())?;

        let (payload, _header) = jwt::decode_with_decrypter(jwe, &decrypter)?;
        let subject = payload
            .subject()
            .expect("Failed to get `sub` from decrypted JWT");

        Ok(subject.to_string())
    }

    fn get_public_key(&self) -> Result<JWK, Self::Error> {
        unimplemented!()
    }
}
