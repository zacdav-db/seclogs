//! Python extension module bindings.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyfunction]
fn generate_events_json(config_json: &str, max_events: Option<usize>) -> PyResult<Vec<String>> {
    crate::api::generate_events_json(config_json, max_events).map_err(to_py_value_error)
}

#[pyfunction]
fn generate_identities_json(population_json: &str) -> PyResult<Vec<String>> {
    crate::api::generate_identities_json(population_json).map_err(to_py_value_error)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_events_json, m)?)?;
    m.add_function(wrap_pyfunction!(generate_identities_json, m)?)?;
    Ok(())
}

fn to_py_value_error(err: Box<dyn std::error::Error>) -> PyErr {
    PyValueError::new_err(err.to_string())
}
