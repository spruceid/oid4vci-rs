use std::ops::Deref;

pub mod discoverable;
pub mod http;

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
