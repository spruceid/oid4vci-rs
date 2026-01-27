#[cfg(feature = "axum")]
mod axum;
pub mod metadata;

pub use metadata::AuthorizationServerMetadata;

#[cfg(feature = "axum")]
pub use axum::*;
