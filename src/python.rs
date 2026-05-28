//! Python extension module bindings.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass(name = "EventStream", unsendable)]
struct PyEventStream {
    inner: crate::api::EventStream,
}

#[pymethods]
impl PyEventStream {
    #[staticmethod]
    fn from_json(config_json: &str) -> PyResult<Self> {
        Ok(Self {
            inner: crate::api::EventStream::from_json(config_json).map_err(to_py_value_error)?,
        })
    }

    #[staticmethod]
    fn from_toml(config_toml: &str) -> PyResult<Self> {
        Ok(Self {
            inner: crate::api::EventStream::from_toml(config_toml).map_err(to_py_value_error)?,
        })
    }

    fn next_event_json(&mut self) -> PyResult<Option<String>> {
        crate::api::EventStream::next_event_json(&mut self.inner).map_err(to_py_value_error)
    }

    fn next_batch_json(&mut self, max_events: usize) -> PyResult<Vec<String>> {
        crate::api::EventStream::next_batch_json(&mut self.inner, max_events)
            .map_err(to_py_value_error)
    }
}

#[pyfunction]
fn generate_events_json(config_json: &str, max_events: Option<usize>) -> PyResult<Vec<String>> {
    crate::api::generate_events_json(config_json, max_events).map_err(to_py_value_error)
}

#[pyfunction]
fn generate_events_toml(config_toml: &str, max_events: Option<usize>) -> PyResult<Vec<String>> {
    crate::api::generate_events_toml(config_toml, max_events).map_err(to_py_value_error)
}

#[pyfunction]
fn generate_identities_json(population_json: &str) -> PyResult<Vec<String>> {
    crate::api::generate_identities_json(population_json).map_err(to_py_value_error)
}

#[pyfunction]
fn generate_identities_toml(population_toml: &str) -> PyResult<Vec<String>> {
    crate::api::generate_identities_toml(population_toml).map_err(to_py_value_error)
}

#[pyfunction]
fn config_toml_to_json(config_toml: &str) -> PyResult<String> {
    crate::api::config_toml_to_json(config_toml).map_err(to_py_value_error)
}

#[pyfunction]
fn population_toml_to_json(population_toml: &str) -> PyResult<String> {
    crate::api::population_toml_to_json(population_toml).map_err(to_py_value_error)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEventStream>()?;
    m.add_function(wrap_pyfunction!(generate_events_json, m)?)?;
    m.add_function(wrap_pyfunction!(generate_events_toml, m)?)?;
    m.add_function(wrap_pyfunction!(generate_identities_json, m)?)?;
    m.add_function(wrap_pyfunction!(generate_identities_toml, m)?)?;
    m.add_function(wrap_pyfunction!(config_toml_to_json, m)?)?;
    m.add_function(wrap_pyfunction!(population_toml_to_json, m)?)?;
    Ok(())
}

fn to_py_value_error(err: Box<dyn std::error::Error>) -> PyErr {
    PyValueError::new_err(err.to_string())
}
