use std::time::Duration;

/// Error while configuring a rate controller.
#[derive(Debug)]
pub enum RateError {
    MissingRate,
    InvalidRate { name: &'static str, value: f64 },
}

impl std::fmt::Display for RateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateError::MissingRate => write!(f, "either events_per_second or bytes_per_second is required"),
            RateError::InvalidRate { name, value } => {
                write!(f, "invalid {name}: {value}")
            }
        }
    }
}

impl std::error::Error for RateError {}

/// Computes how many events should be emitted for a time slice.
pub struct RateController {
    events_per_second: Option<f64>,
    bytes_per_second: Option<f64>,
    carry_events: f64,
    carry_bytes: f64,
}

impl RateController {
    /// Creates a new controller from events/sec or bytes/sec targets.
    pub fn new(
        events_per_second: Option<f64>,
        bytes_per_second: Option<u64>,
    ) -> Result<Self, RateError> {
        let events_per_second = events_per_second.map(|value| {
            if !value.is_finite() || value <= 0.0 {
                Err(RateError::InvalidRate {
                    name: "events_per_second",
                    value,
                })
            } else {
                Ok(value)
            }
        }).transpose()?;

        let bytes_per_second = bytes_per_second.map(|value| {
            let value = value as f64;
            if !value.is_finite() || value <= 0.0 {
                Err(RateError::InvalidRate {
                    name: "bytes_per_second",
                    value,
                })
            } else {
                Ok(value)
            }
        }).transpose()?;

        if events_per_second.is_none() && bytes_per_second.is_none() {
            return Err(RateError::MissingRate);
        }

        Ok(Self {
            events_per_second,
            bytes_per_second,
            carry_events: 0.0,
            carry_bytes: 0.0,
        })
    }

    /// Returns the event quota for the elapsed time window.
    pub fn quota(
        &mut self,
        elapsed: Duration,
        multiplier: f64,
        avg_event_size_bytes: u64,
    ) -> u64 {
        if elapsed.is_zero() {
            return 0;
        }

        if let Some(events_per_second) = self.events_per_second {
            let target = events_per_second * multiplier * elapsed.as_secs_f64() + self.carry_events;
            let emit = target.floor().max(0.0) as u64;
            self.carry_events = target - emit as f64;
            return emit;
        }

        if let Some(bytes_per_second) = self.bytes_per_second {
            let avg = avg_event_size_bytes.max(1) as f64;
            let target_bytes = bytes_per_second * multiplier * elapsed.as_secs_f64() + self.carry_bytes;
            let emit = (target_bytes / avg).floor().max(0.0) as u64;
            self.carry_bytes = target_bytes - emit as f64 * avg;
            return emit;
        }

        0
    }
}
