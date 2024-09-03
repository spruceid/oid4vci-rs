use std::fmt::{Debug, Error as FormatterError, Formatter};
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use anyhow::bail;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

macro_rules! new_type {
    // Convenience pattern without an impl.
    (
        $(#[$attr:meta])*
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        )
    ) => {
        new_type![
            $(#[$attr])*
            $name(
                $(#[$type_attr])*
                $type
            )
            impl {}
        ];
    };
    // Main entry point with an impl.
    (
        $(#[$attr:meta])*
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        )
        impl {
            $($item:tt)*
        }
    ) => {
        new_type![
            @new_type $(#[$attr])*,
            $name(
                $(#[$type_attr])*
                $type
            ),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            impl {
                $($item)*
            }
        ];
    };
    // Actual implementation, after stringifying the #[doc] attr.
    (
        @new_type $(#[$attr:meta])*,
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        ),
        $new_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(#[$attr])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name(
            $(#[$type_attr])*
            $type
        );
        impl $name {
            $($item)*

            #[doc = $new_doc]
            pub const fn new(s: $type) -> Self {
                $name(s)
            }
        }
        impl Deref for $name {
            type Target = $type;
            fn deref(&self) -> &$type {
                &self.0
            }
        }
        impl From<$name> for $type {
            fn from(s: $name) -> $type {
                s.0
            }
        }
    }
}

macro_rules! new_secret_type {
    (
        $(#[$attr:meta])*
        $name:ident($type:ty)
    ) => {
        new_secret_type![
            $(#[$attr])*
            $name($type)
            impl {}
        ];
    };
    (
        $(#[$attr:meta])*
        $name:ident($type:ty)
        impl {
            $($item:tt)*
        }
    ) => {
        new_secret_type![
            $(#[$attr])*,
            $name($type),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            concat!("Get the secret contained within this `", stringify!($name), "`."),
            impl {
                $($item)*
            }
        ];
    };
    (
        $(#[$attr:meta])*,
        $name:ident($type:ty),
        $new_doc:expr,
        $secret_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(
            #[$attr]
        )*
        pub struct $name($type);
        impl $name {
            $($item)*

            #[doc = $new_doc]
            pub fn new(s: $type) -> Self {
                $name(s)
            }
            #[doc = $secret_doc]
            ///
            /// # Security Warning
            ///
            /// Leaking this value may compromise the security of the OAuth2 flow.
            pub fn secret(&self) -> &$type { &self.0 }
        }
        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
                write!(f, concat!(stringify!($name), "([redacted])"))
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                Sha256::digest(&self.0) == Sha256::digest(&other.0)
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                Sha256::digest(&self.0).hash(state)
            }
        }

    };
}

///
/// Creates a URL-specific new type
///
/// Types created by this macro enforce during construction that the contained value represents a
/// syntactically valid URL. However, comparisons and hashes of these types are based on the string
/// representation given during construction, disregarding any canonicalization performed by the
/// underlying `Url` struct. OpenID Connect requires certain URLs (e.g., ID token issuers) to be
/// compared exactly, without canonicalization.
///
/// In addition to the raw string representation, these types include a `url` method to retrieve a
/// parsed `Url` struct.
///
macro_rules! new_url_type {
    // Convenience pattern without an impl.
    (
        $(#[$attr:meta])*
        $name:ident
    ) => {
        new_url_type![
            $(#[$attr])*
            $name
            impl {}
        ];
    };
    // Main entry point with an impl.
    (
        $(#[$attr:meta])*
        $name:ident
        impl {
            $($item:tt)*
        }
    ) => {
        new_url_type![
            @new_type_pub $(#[$attr])*,
            $name,
            concat!("Create a new `", stringify!($name), "` from a `String` to wrap a URL."),
            concat!("Create a new `", stringify!($name), "` from a `Url` to wrap a URL."),
            concat!("Return this `", stringify!($name), "` as a parsed `Url`."),
            impl {
                $($item)*
            }
        ];
    };
    // Actual implementation, after stringifying the #[doc] attr.
    (
        @new_type_pub $(#[$attr:meta])*,
        $name:ident,
        $new_doc:expr,
        $from_url_doc:expr,
        $url_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(#[$attr])*
        #[derive(Clone)]
        pub struct $name(Url, String);
        impl $name {
            #[doc = $new_doc]
            pub fn new(url: String) -> Result<Self, ::url::ParseError> {
                Ok($name(Url::parse(&url)?, url))
            }
            #[doc = $from_url_doc]
            pub fn from_url(url: Url) -> Self {
                let s = url.to_string();
                Self(url, s)
            }
            #[doc = $url_doc]
            pub fn url(&self) -> &Url {
                return &self.0;
            }
            $($item)*
        }
        impl Deref for $name {
            type Target = String;
            fn deref(&self) -> &String {
                &self.1
            }
        }
        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
                let mut debug_trait_builder = f.debug_tuple(stringify!($name));
                debug_trait_builder.field(&self.1);
                debug_trait_builder.finish()
            }
        }
        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::de::Deserializer<'de>,
            {
                struct UrlVisitor;
                impl<'de> ::serde::de::Visitor<'de> for UrlVisitor {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut ::std::fmt::Formatter
                    ) -> ::std::fmt::Result {
                        formatter.write_str(stringify!($name))
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        $name::new(v.to_string()).map_err(E::custom)
                    }
                }
                deserializer.deserialize_str(UrlVisitor {})
            }
        }
        impl ::serde::Serialize for $name {
            fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
            where
                SE: ::serde::Serializer,
            {
                serializer.serialize_str(&self.1)
            }
        }
        impl ::std::hash::Hash for $name {
            fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) -> () {
                ::std::hash::Hash::hash(&(self.1), state);
            }
        }
        impl Ord for $name {
            fn cmp(&self, other: &$name) -> ::std::cmp::Ordering {
                self.1.cmp(&other.1)
            }
        }
        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &$name) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        impl PartialEq for $name {
            fn eq(&self, other: &$name) -> bool {
                self.1 == other.1
            }
        }
        impl Eq for $name {}
    };
}

new_url_type![
    /// Base URL of the [Credential] Issuer.
    IssuerUrl
    impl {
        /// Parse a string as a URL, with this URL as the base URL.
        ///
        /// See [`Url::parse`].
        pub fn join(&self, suffix: &str) -> Result<Url, url::ParseError> {
            if let Some('/') = self.1.chars().next_back() {
                Url::parse(&(self.1.clone() + suffix))
            } else {
                Url::parse(&(self.1.clone() + "/" + suffix))
            }
        }
    }
];

new_url_type![
    /// The credential offer request as a URL, as represented in a QR code or deep link.
    CredentialOfferRequest
    impl {
        const DEFAULT_URL_SCHEME: &'static str = "openid-credential-offer";

        /// Parse the credential offer request from a URL, and validate that the URL scheme is
        /// `scheme`.
        pub fn from_url_checked_with_scheme(url: Url, expected_scheme: &str) -> Result<Self, anyhow::Error> {
            let this = Self::from_url(url);
            let this_scheme = this.url().scheme();
            if this_scheme != expected_scheme {
                bail!("unexpected URL scheme '{this_scheme}', expected '{expected_scheme}'")
            }
            Ok(this)
        }

        /// Parse the credential offer request from a URL, and validate that the URL scheme is
        /// `openid-credential-offer`.
        pub fn from_url_checked(url: Url) -> Result<Self, anyhow::Error> {
            Self::from_url_checked_with_scheme(url, Self::DEFAULT_URL_SCHEME)
        }
    }
];

new_url_type![
    /// URL of the Credential Issuer's Credential Endpoint.
    CredentialUrl
];

new_url_type![
    /// URL of the Credential Issuer's Batch Credential Endpoint.
    BatchCredentialUrl
];

new_url_type![
    /// URL of the Credential Issuer's Deferred Credential Endpoint.
    DeferredCredentialUrl
];

new_url_type![
    /// URL of the Pushed Authorization Request Endpoint.
    ParUrl
];

new_url_type![
    /// URL of the Credential Issuer's Notification Endpoint
    NotificationUrl
];

new_url_type![
    /// URL of the authorization server's JWK Set document
    /// (see [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517)).
    JsonWebKeySetUrl
];

new_url_type![
    /// URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint
    /// (see [RFC7591](https://datatracker.ietf.org/doc/html/rfc7591)).
    RegistrationUrl
];

new_url_type![
    /// A URI where the Wallet can obtain the logo of the Credential from the Credential Issuer.
    /// The Wallet needs to determine the scheme, since the URI value could use the `https:` scheme,
    /// the `data:` scheme, etc.
    LogoUri
];

new_type![
    /// String value that identifies the language of this object represented as a language tag taken
    /// from values defined in [BCP47 (RFC5646)](https://www.rfc-editor.org/rfc/rfc5646.html).
    #[derive(Deserialize, Serialize, Eq, Hash)]
    LanguageTag(String)
];

new_type![
    /// String value of a background color of the Credential represented as numerical color values
    /// defined in [CSS Color Module Level 37](https://www.w3.org/TR/css-color-3).
    #[derive(Deserialize, Serialize, Eq, Hash)]
    BackgroundColor(String)
];

new_type![
    /// String value of a text color of the Credential represented as numerical color values
    /// defined in [CSS Color Module Level 37](https://www.w3.org/TR/css-color-3).
    #[derive(Deserialize, Serialize, Eq, Hash)]
    TextColor(String)
];

new_type![
    #[derive(Deserialize, Serialize, Eq, Hash)]
    ResponseMode(String)
];

new_type![
    #[derive(Deserialize, Eq, Hash, Ord, PartialOrd, Serialize)]
    JsonWebTokenContentType(String)
];

new_type![
    #[derive(Deserialize, Eq, Hash, Ord, PartialOrd, Serialize)]
    JsonWebTokenType(String)
];

new_secret_type![
    #[derive(Deserialize, Serialize, Clone)]
    Nonce(String)
    impl {
        pub fn new_random() -> Self {
            use base64::prelude::*;
            Self(BASE64_URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()))
        }
    }
];

new_secret_type![
    #[derive(Deserialize, Serialize, Clone)]
    PreAuthorizedCode(String)
];

new_secret_type![
    #[derive(Deserialize, Serialize, Clone)]
    IssuerState(String)
];

new_secret_type![
    #[derive(Deserialize, Serialize)]
    UserHint(String)
];

new_secret_type![
    #[derive(Deserialize, Serialize)]
    TxCode(String)
];
