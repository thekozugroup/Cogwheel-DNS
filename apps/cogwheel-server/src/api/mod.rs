//! The handlers behind the twenty JSON routes of §3, one module per resource.

pub mod check;
pub mod devices;
pub mod lists;
pub mod overview;
pub mod queries;
pub mod rules;
pub mod runtime;
pub mod settings;

use crate::http::ApiError;
use serde::Serialize;

/// The body every DELETE answers with.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Deleted {
    pub deleted: bool,
}

/// Trim a field the caller has to fill in, refusing it when nothing is left.
///
/// A name is the only such field in the product — a device's and a list's — and both are stored
/// as typed, so they are trimmed the same way and refused with the same status.
pub fn non_empty(value: &str, message: &'static str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(message));
    }
    Ok(trimmed.to_owned())
}
