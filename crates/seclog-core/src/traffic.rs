use crate::config::{CurveConfig, TrafficConfig, TrafficMode, WeekdayPeakCurve};
use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use chrono_tz::Tz;
use std::str::FromStr;

/// Errors while building a traffic model.
#[derive(Debug)]
pub enum TrafficError {
    EmptyTimezones,
    InvalidTimezone { name: String },
    InvalidWeight { name: String, weight: f64 },
}

impl std::fmt::Display for TrafficError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrafficError::EmptyTimezones => write!(f, "timezone distribution is empty"),
            TrafficError::InvalidTimezone { name } => write!(f, "invalid timezone: {name}"),
            TrafficError::InvalidWeight { name, weight } => {
                write!(f, "invalid timezone weight for {name}: {weight}")
            }
        }
    }
}

impl std::error::Error for TrafficError {}

/// Computes traffic multipliers based on time and timezone mix.
pub struct TrafficModel {
    mode: TrafficMode,
    curve: Option<CurveConfig>,
    timezones: Vec<(Tz, f64)>,
}

impl TrafficModel {
    /// Creates a traffic model from config.
    pub fn from_config(config: &TrafficConfig) -> Result<Self, TrafficError> {
        let timezones = match &config.timezone_distribution {
            Some(list) if list.is_empty() => return Err(TrafficError::EmptyTimezones),
            Some(list) => list
                .iter()
                .map(|entry| {
                    if !entry.weight.is_finite() || entry.weight <= 0.0 {
                        return Err(TrafficError::InvalidWeight {
                            name: entry.name.clone(),
                            weight: entry.weight,
                        });
                    }
                    let tz = Tz::from_str(&entry.name)
                        .map_err(|_| TrafficError::InvalidTimezone {
                            name: entry.name.clone(),
                        })?;
                    Ok((tz, entry.weight))
                })
                .collect::<Result<Vec<_>, _>>()?,
            None => vec![(chrono_tz::UTC, 1.0)],
        };

        Ok(Self {
            mode: config.mode.clone(),
            curve: config.curve.clone(),
            timezones,
        })
    }

    /// Returns a multiplier to apply to the base rate at a given time.
    pub fn multiplier(&self, time_utc: DateTime<Utc>) -> f64 {
        match self.mode {
            TrafficMode::Constant => 1.0,
            TrafficMode::Realistic => match &self.curve {
                Some(CurveConfig::WeekdayPeak(curve)) => {
                    weekday_peak_multiplier(time_utc, &self.timezones, curve)
                }
                None => 1.0,
            },
        }
    }
}

fn weekday_peak_multiplier(
    time_utc: DateTime<Utc>,
    timezones: &[(Tz, f64)],
    curve: &WeekdayPeakCurve,
) -> f64 {
    let mut total = 0.0;
    let mut weight_sum = 0.0;

    for (tz, weight) in timezones {
        let local = time_utc.with_timezone(tz);
        let is_weekend = matches!(local.weekday(), Weekday::Sat | Weekday::Sun);
        let mut multiplier = if is_weekend {
            curve.weekend_multiplier
        } else {
            curve.weekday_multiplier
        };
        let hour = local.hour() as u8;
        if curve.peak_hours_local.contains(&hour) {
            multiplier *= curve.peak_multiplier;
        }
        total += multiplier * *weight;
        weight_sum += *weight;
    }

    if weight_sum > 0.0 {
        total / weight_sum
    } else {
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CurveConfig, TimezoneWeight, WeekdayPeakCurve};
    use chrono::TimeZone;

    #[test]
    fn weekend_multiplier_applies() {
        let config = TrafficConfig {
            mode: TrafficMode::Realistic,
            events_per_second: None,
            bytes_per_second: None,
            curve: Some(CurveConfig::WeekdayPeak(WeekdayPeakCurve {
                weekday_multiplier: 1.0,
                weekend_multiplier: 0.5,
                peak_hours_local: vec![9, 10],
                peak_multiplier: 2.0,
            })),
            timezone_distribution: Some(vec![TimezoneWeight {
                name: "UTC".to_string(),
                weight: 1.0,
            }]),
        };

        let model = TrafficModel::from_config(&config).expect("model");
        let saturday = Utc.with_ymd_and_hms(2024, 1, 6, 9, 0, 0).unwrap();
        let multiplier = model.multiplier(saturday);
        assert_eq!(multiplier, 1.0);
    }
}
