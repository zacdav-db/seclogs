//! Seclog library crate.
//!
//! Exposes core types, sources, and output formats for the CLI.

pub mod actors_parquet;
pub mod api;
pub mod core;
pub mod formats;
pub mod sources;

pub use core::activity;
pub use core::actors;
pub use core::config;
pub use core::event;
pub use core::identity;
pub use core::traits;

#[cfg(feature = "python")]
mod python;

#[cfg(feature = "python")]
#[pyo3::pymodule]
fn _native(m: &pyo3::Bound<'_, pyo3::types::PyModule>) -> pyo3::PyResult<()> {
    python::register(m)
}
