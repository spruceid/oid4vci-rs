use ssi::{
    jwk::{Algorithm, JWK},
    jws::Header,
};

pub trait JWSInterface {
    fn encode_sign(&self, bytes: &str) -> Result<String, ssi::error::Error>;
    fn decode_verify(&self, jwt: &str) -> Result<(Header, Vec<u8>), ssi::error::Error>;
}

pub struct SSI {
    jwk: JWK,
    alg: Algorithm,
}

impl JWSInterface for SSI {
    fn encode_sign(&self, bytes: &str) -> Result<String, ssi::error::Error> {
        ssi::jws::encode_sign(self.alg, bytes, &self.jwk)
    }

    fn decode_verify(&self, jwt: &str) -> Result<(Header, Vec<u8>), ssi::error::Error> {
        ssi::jws::decode_verify(jwt, &self.jwk)
    }
}

type Signer = dyn Fn(&[u8]) -> Result<Vec<u8>, ssi::error::Error>;
type Verifier = dyn Fn(Algorithm, &[u8], &[u8]) -> Result<(), ssi::error::Error>;

pub struct JWSExternal {
    header: Header,
    signer: Box<Signer>,
    verifier: Box<Verifier>,
}

impl JWSInterface for JWSExternal {
    fn encode_sign(&self, bytes: &str) -> Result<String, ssi::error::Error> {
        let header_b64 = ssi::vc::base64_encode_json(&self.header)?;
        let payload_b64 = base64::encode_config(bytes, base64::URL_SAFE_NO_PAD);
        let signing_input = header_b64 + "." + &payload_b64;
        let signature = self.signer.call((signing_input.as_bytes(),))?;
        let signature_b64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
        let jwt = signing_input + "." + &signature_b64;
        Ok(jwt)
    }

    fn decode_verify(&self, jwt: &str) -> Result<(Header, Vec<u8>), ssi::error::Error> {
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
}
