# OID4VCI for Rust

<!-- cargo-rdme start -->

This library provides a Rust implementation of [OID4VCI draft-13].

[OID4VCI draft-13]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-pre-authorized-code-flow>

## Protocol Overview

Here is a simplified overview of the OID4VCI protocol, referencing the
various types and methods implementing it.

### Offer

1. *Out-of-band credential offer*: Issuer sends a [`CredentialOffer`] to the
   Wallet. This can be done through various methods like a QR-code, deep
   link, etc.
2. *Issuer metadata resolution*: Wallet fetches the
   [`CredentialIssuerMetadata`]. This object is [`Discoverable`] behind the
   `/.well-known/openid-credential-issuer` endpoint.

All the code related to Credential Offer is located in the
[`offer`] module.

[`CredentialOffer`]: https://docs.rs/oid4vci/latest/oid4vci/offer/enum.CredentialOffer.html
[`CredentialIssuerMetadata`]: https://docs.rs/oid4vci/latest/oid4vci/issuer/metadata/struct.CredentialIssuerMetadata.html
[`Discoverable`]: https://docs.rs/oid4vci/latest/oid4vci/util/discoverable/trait.Discoverable.html

### Authorization

3. *Authorization server resolution*: Wallet fetches the
   [`AuthorizationServerMetadata`]. This object is [`Discoverable`] behind
   the `/.well-known/oauth-authorization-server` endpoint.
4. Wallet sends an [`AuthorizationRequest`] to the Authorization Server,
   specifying what types of Credential(s) it is ready to be issued.
5. Authorization Server returns an [`AuthorizationCode`].
6. Wallet sends a Token Request.
7. Authorization Server returns a Token Response, with an Access Token.

All the code related to Authorization is located in the [`authorization`]
module.

[`AuthorizationServerMetadata`]: https://docs.rs/oid4vci/latest/oid4vci/authorization/server/metadata/struct.AuthorizationServerMetadata.html
[`AuthorizationRequest`]: https://docs.rs/oid4vci/latest/oid4vci/authorization/struct.AuthorizationRequest.html
[`AuthorizationCode`]: oauth2::AuthorizationCode

### Issuance

8. Wallet sends a [`CredentialRequest`] to the Issuer, with the Access Token.
9. Issuer returns a [`CredentialResponse`], with the Credential(s).

[`CredentialRequest`]: https://docs.rs/oid4vci/latest/oid4vci/request/struct.CredentialRequest.html
[`CredentialResponse`]: https://docs.rs/oid4vci/latest/oid4vci/response/struct.CredentialResponse.html

<!-- cargo-rdme end -->
