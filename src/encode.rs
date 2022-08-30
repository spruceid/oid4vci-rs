use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Serialize, Serializer};

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
