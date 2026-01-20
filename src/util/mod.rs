pub mod discoverable;
pub mod http;

pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}
