use ssi::{
    jwk::{Algorithm, JWK},
    jws::Header,
};

pub trait JOSEInterface {
    type Error;

    fn jwt_encode_sign(&self, bytes: &str) -> Result<String, Self::Error>;
    fn jwt_decode_verify(&self, jwt: &str) -> Result<(Header, Vec<u8>), Self::Error>;

    // TODO: for pre-authz_code user_pin
    // fn jwe_encrypt(&self, bytes: &str) -> Result<String, Self::Error>;
    // fn jwe_decrypt(&self, jwe: &str) -> Result<(Header, Vec<u8>), Self::Error>;

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

    fn get_public_key(&self) -> Result<JWK, Self::Error> {
        unimplemented!()
    }
}

type Signer<E> = dyn Fn(&[u8]) -> Result<Vec<u8>, E>;
type Verifier<E> = dyn Fn(Algorithm, &[u8], &[u8]) -> Result<(), E>;

pub struct JOSEExternal<E> {
    header: Header,
    signer: Box<Signer<E>>,
    verifier: Box<Verifier<E>>,
}

impl<E> JOSEInterface for JOSEExternal<E>
where
    E: From<ssi::jws::Error> + From<ssi::vc::Error>,
{
    type Error = E;

    fn jwt_encode_sign(&self, bytes: &str) -> Result<String, Self::Error> {
        let header_b64 = ssi::vc::base64_encode_json(&self.header)?;
        let payload_b64 = base64::encode_config(bytes, base64::URL_SAFE_NO_PAD);
        let signing_input = header_b64 + "." + &payload_b64;
        let signature = self.signer.call((signing_input.as_bytes(),))?;
        let signature_b64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
        let jwt = signing_input + "." + &signature_b64;
        Ok(jwt)
    }

    fn jwt_decode_verify(&self, jwt: &str) -> Result<(Header, Vec<u8>), Self::Error> {
        let (header_b64, payload_enc, signature_b64) = ssi::jws::split_jws(jwt)?;
        let ssi::jws::DecodedJWS {
            header,
            signing_input,
            payload,
            signature,
        } = ssi::jws::decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?;
        self.verifier
            .call((header.algorithm, &signing_input, &signature))?;
        Ok((header, payload))
    }

    fn get_public_key(&self) -> Result<JWK, Self::Error> {
        unimplemented!()
    }
}
