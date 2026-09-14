//! The handlers behind the twenty JSON routes of §3, one module per resource.

pub mod check;
pub mod devices;
pub mod lists;
pub mod overview;
pub mod queries;
pub mod rules;
pub mod runtime;
pub mod settings;

use serde::Serialize;

/// The body every DELETE answers with.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Deleted {
    pub deleted: bool,
}
