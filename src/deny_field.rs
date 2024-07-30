use serde::Deserializer;

pub(crate) fn deny_field<'de, D>(_deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    Err(serde::de::Error::custom("Field must not be present"))
}
