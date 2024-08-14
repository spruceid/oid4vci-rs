use serde::Deserializer;

/// When using flattened structs with `serde`, it is not possible
/// to also use #[serde(deny_unknown_fields)] in the same struct
/// definition, but it is possible to create a custom deserializer
/// that just errors to be able to deny a specific field instead.
/// In this library, this is used mainly to implement parameter
/// either/or situations, such as when either `format` or
/// `credential_configuration_id` must be present, but not
/// both in `AuthorizationDetails`.
pub(crate) fn deny_field<'de, D>(_deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    Err(serde::de::Error::custom("Field must not be present"))
}
