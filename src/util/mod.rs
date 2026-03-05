use std::ops::Deref;

use ssi::claims::jwt::IssuedAt;
use ssi::claims::{
    chrono::{DateTime, Utc},
    jwt::NumericDate,
};

pub mod http;
pub mod no_signer;

pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}

pub fn non_empty<T, A: Deref<Target = [T]>>(array: A) -> Option<A> {
    if array.is_empty() {
        None
    } else {
        Some(array)
    }
}

pub fn jwt_iat_now() -> IssuedAt {
    IssuedAt(jwt_numeric_date(Utc::now()))
}

#[cfg(feature = "integer-ts")]
pub fn jwt_numeric_date(d: DateTime<Utc>) -> NumericDate {
    d.timestamp().try_into().unwrap()
}

#[cfg(not(feature = "integer-ts"))]
pub fn jwt_numeric_date(d: DateTime<Utc>) -> NumericDate {
    d.into()
}
