use crate::{
    offer::CredentialOfferParameters, profile::ProfileCredentialIssuerMetadata, Profile,
    StandardProfile,
};

/// Resolved Credential Offer.
///
/// Contains the credential offer parameters and issuer metadata, fetched from
/// the initial offer.
///
/// Can be used with [`Oid4vciClient::accept_offer`] to get a
/// [`CredentialToken`].
///
/// [`Oid4vciClient::accept_offer`]: crate::Oid4vciClient::accept_offer
/// [`CredentialToken`]: crate::client::CredentialToken
#[derive(Debug)]
pub struct ResolvedCredentialOffer<P: Profile = StandardProfile> {
    pub params: CredentialOfferParameters,
    pub issuer_metadata: ProfileCredentialIssuerMetadata<P>,
}

impl<P: Profile> Clone for ResolvedCredentialOffer<P> {
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
            issuer_metadata: self.issuer_metadata.clone(),
        }
    }
}
