use chrono::prelude::*;
use ssi::vc::VCDateTime;

use crate::{jwk::*, PreAuthzCode, Proof, ProofOfPossession, TokenResponse};

pub fn verify_token_response<I>(
    token: String,
    interface: &I,
) -> Result<TokenResponse, ssi::error::Error>
where
    I: JWSInterface,
{
    let (_, bytes) = interface.decode_verify(&token)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn verify_preauthz_code<I>(
    preauthz_code: String,
    interface: &I,
) -> Result<PreAuthzCode, ssi::error::Error>
where
    I: JWSInterface,
{
    let (_, bytes) = interface.decode_verify(&preauthz_code)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn verify_credential_request<I>(_interface: &I) -> Result<(), ssi::error::Error>
where
    I: JWSInterface,
{
    Ok(())
}

fn to_datetime(vcdatetime: VCDateTime) -> Result<DateTime<FixedOffset>, ssi::error::Error> {
    let datetime: String = vcdatetime.into();
    DateTime::parse_from_rfc3339(&datetime).map_err(|_| ssi::error::Error::TimeError)
}

pub fn verify_proof_of_possession<I>(
    _proof: &Proof,
    _interface: &I,
) -> Result<String, ssi::error::Error>
where
    I: JWSInterface,
{
    // match proof {
    //     Proof::JWT { jwt, .. } => {
    //         let (header, pop): (_, ProofOfPossession) = {
    //             let (header, bytes) = interface.decode_verify(jwt)?;
    //             (header, serde_json::from_slice(&bytes)?)
    //         };

    //         let now = Utc::now();
    //         let exp = to_datetime(pop.expires_at)?;
    //         if now > exp {
    //             return Err(ssi::error::Error::ExpiredProof);
    //         }

    //         if header.key_id.is_none() {
    //             return Err(ssi::error::Error::Key);
    //         }

    //         Ok(header.key_id.unwrap())
    //     }
    // }

    Ok("wip".into())
}
