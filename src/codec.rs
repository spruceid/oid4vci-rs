use chrono::prelude::*;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Serialize, Serializer};
use ssi::vc::VCDateTime;

pub fn to_percent_encode<S>(x: &str, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&utf8_percent_encode(x, NON_ALPHANUMERIC).to_string())
}

pub fn collect_into_url<T: Serialize>(params: &T) -> String {
    let params = serde_json::to_value(params).unwrap();
    params
        .as_object()
        .unwrap()
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v.as_str().unwrap_or(&v.to_string())))
        .collect::<Vec<_>>()
        .join("&")
}

pub struct ToDateTime;

impl ToDateTime {
    pub fn from_vcdatetime(
        vcdatetime: VCDateTime,
    ) -> Result<DateTime<FixedOffset>, ssi::vc::Error> {
        let datetime: String = vcdatetime.into();
        DateTime::parse_from_rfc3339(&datetime).map_err(|_| ssi::vc::Error::TimeError)
    }

    pub fn from_str(value: &str) -> Result<DateTime<FixedOffset>, ssi::vc::Error> {
        DateTime::parse_from_rfc3339(value).map_err(|_| ssi::vc::Error::TimeError)
    }
}
