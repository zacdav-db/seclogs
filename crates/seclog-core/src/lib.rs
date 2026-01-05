//! Core types and utilities for seclog sources and sinks.
//!
//! This crate defines the shared event schema, configuration types, actor
//! modeling, and rate/traffic helpers used by generators and writers.

pub mod actors;
pub mod config;
pub mod event;
pub mod rate;
pub mod traffic;
pub mod traits;
