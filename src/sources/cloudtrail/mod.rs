//! CloudTrail-style event generator.
//!
//! Provides catalog-driven event selection and a `CloudTrailGenerator` source.

pub mod catalog;
pub mod generator;
pub mod model;
pub mod templates;

pub use catalog::{
    resolve_event_weights, resolve_selector, CatalogError, EventSelector, WeightedEvent,
};
pub use generator::CloudTrailGenerator;
pub use model::{CloudTrailEvent, UserIdentity};
pub use templates::{
    apply_error, build_cloudtrail_event, default_error_profile, ActorContext, ErrorProfile,
    TemplateError,
};
