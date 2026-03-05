use crate::client::{CredentialToken, Oid4vciClient, SimpleOid4vciClient};

mod authorization_code;
mod tx_code;

pub use authorization_code::*;
pub use tx_code::*;

/// Credential Token State.
///
/// When querying a Credential Authorization Token to the Authorization Server,
/// it may ask for further authentication. This can be either querying an
/// Authorization Code, or a Transaction Code for Pre-Authorized Code grants.
/// If the Pre-Authorized Code grant doesn't require a Transaction Code, the
/// token will directly be `Ready`.
pub enum CredentialTokenState<C: Oid4vciClient = SimpleOid4vciClient> {
    /// Credential Token requires an Authorization Code.
    RequiresAuthorizationCode(AuthorizationCodeRequired<C>),

    /// Credential Token requires a Transaction Code.
    RequiresTxCode(TxCodeRequired<C>),

    /// Credential Token is ready.
    Ready(CredentialToken<C::Profile>),
}
