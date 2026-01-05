use clap::{Parser, Subcommand};
use chrono::Utc;
use seclog_core::config::{Config, FormatConfig, SourceConfig};
use seclog_core::rate::RateController;
use seclog_core::traffic::TrafficModel;
use seclog_core::traits::{EventSource, EventWriter};
use seclog_formats_jsonl::JsonlWriter;
use seclog_formats_parquet::ParquetWriter;
use seclog_sources_cloudtrail::CloudTrailGenerator;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
#[command(name = "seclog")]
#[command(about = "SIEM log generator", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Gen {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        max_events: Option<u64>,
        #[arg(long)]
        max_seconds: Option<u64>,
        #[arg(long, default_value_t = 1000)]
        metrics_interval_ms: u64,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Gen {
            config,
            output,
            dry_run,
            max_events,
            max_seconds,
            metrics_interval_ms,
        } => {
            let mut loaded = Config::from_path(&config)?;

            if let Some(dir) = output {
                loaded.output.dir = dir.to_string_lossy().to_string();
            }

            if dry_run {
                println!("config loaded: {loaded:#?}");
                return Ok(());
            }

            let traffic_model = TrafficModel::from_config(&loaded.traffic)?;
            let mut rate_controller = RateController::new(
                loaded.traffic.events_per_second,
                loaded.traffic.bytes_per_second,
            )?;

            let mut sources = Vec::new();
            for (idx, source) in loaded.sources.iter().enumerate() {
                match source {
                    SourceConfig::CloudTrail(config) => {
                        let seed = loaded.seed.map(|value| value + idx as u64);
                        let generator = CloudTrailGenerator::from_config(config, seed)?;
                        sources.push(Box::new(generator) as Box<dyn EventSource>);
                    }
                }
            }

            if sources.is_empty() {
                return Err("no sources configured".into());
            }

            let mut writers: Vec<Box<dyn EventWriter>> = Vec::new();
            for format in &loaded.output.formats {
                match format {
                    FormatConfig::Jsonl(_) => {
                        writers.push(Box::new(JsonlWriter::new(
                            &loaded.output.dir,
                            loaded.output.rotation.target_size_mb,
                        )?));
                    }
                    FormatConfig::Parquet(_) => {
                        writers.push(Box::new(ParquetWriter::new(
                            &loaded.output.dir,
                            loaded.output.rotation.target_size_mb,
                        )?));
                    }
                }
            }

            if writers.is_empty() {
                return Err("no output formats configured".into());
            }

            let mut router = SourceRouter::new(sources);
            let tick = Duration::from_millis(100);
            let mut last_tick = Instant::now();
            let mut avg_event_size: f64 = 1024.0;
            let mut total_events = 0_u64;

            let flush_interval = loaded
                .output
                .rotation
                .flush_interval_ms
                .map(Duration::from_millis);
            let mut next_flush = flush_interval.map(|interval| Instant::now() + interval);
            let mut metrics = Metrics::new(Duration::from_millis(metrics_interval_ms));
            let start_time = Instant::now();
            let max_duration = max_seconds.map(Duration::from_secs);

            loop {
                let loop_start = Instant::now();
                if let Some(limit) = max_duration {
                    if loop_start.duration_since(start_time) >= limit {
                        break;
                    }
                }
                let elapsed = loop_start.saturating_duration_since(last_tick);
                if elapsed < tick {
                    std::thread::sleep(tick - elapsed);
                    continue;
                }
                last_tick = loop_start;

                let multiplier = traffic_model.multiplier(Utc::now());
                let mut budget =
                    rate_controller.quota(elapsed, multiplier, avg_event_size.round() as u64);

                if let Some(max) = max_events {
                    if total_events >= max {
                        break;
                    }
                    let remaining = max - total_events;
                    if budget > remaining {
                        budget = remaining;
                    }
                }

                if budget == 0 {
                    continue;
                }

                let mut loop_events = 0_u64;
                let mut loop_bytes = 0_u64;

                for _ in 0..budget {
                    let event = match router.next_event() {
                        Some(event) => event,
                        None => continue,
                    };

                    let mut total_bytes = 0_u64;
                    for writer in writers.iter_mut() {
                        total_bytes += writer.write_event(&event)?;
                    }

                    if total_bytes > 0 {
                        let alpha = 0.1;
                        avg_event_size =
                            (1.0 - alpha) * avg_event_size + alpha * total_bytes as f64;
                    }

                    total_events += 1;
                    loop_events += 1;
                    loop_bytes += total_bytes;
                }

                if let (Some(interval), Some(next)) = (flush_interval, next_flush) {
                    if loop_start >= next {
                        for writer in writers.iter_mut() {
                            writer.flush()?;
                        }
                        next_flush = Some(loop_start + interval);
                    }
                }

                let overrun = loop_start.elapsed().saturating_sub(tick);
                let indicate_missed = budget.saturating_sub(loop_events);
                metrics.record(loop_events, loop_bytes, overrun, indicate_missed);
            }

            for writer in writers.iter_mut() {
                writer.close()?;
            }
        }
    }

    Ok(())
}

struct SourceRouter {
    sources: Vec<Box<dyn EventSource>>,
    index: usize,
}

impl SourceRouter {
    fn new(sources: Vec<Box<dyn EventSource>>) -> Self {
        Self { sources, index: 0 }
    }

    fn next_event(&mut self) -> Option<seclog_core::event::Event> {
        if self.sources.is_empty() {
            return None;
        }

        let total = self.sources.len();
        for _ in 0..total {
            let idx = self.index % total;
            self.index = (self.index + 1) % total;
            if let Some(event) = self.sources[idx].next_event() {
                return Some(event);
            }
        }

        None
    }
}

struct Metrics {
    interval: Duration,
    last_report: Instant,
    events: u64,
    bytes: u64,
    overruns: Duration,
    missed_events: u64,
}

impl Metrics {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_report: Instant::now(),
            events: 0,
            bytes: 0,
            overruns: Duration::ZERO,
            missed_events: 0,
        }
    }

    fn record(&mut self, events: u64, bytes: u64, overrun: Duration, missed: u64) {
        self.events += events;
        self.bytes += bytes;
        self.overruns += overrun;
        self.missed_events += missed;

        let elapsed = self.last_report.elapsed();
        if elapsed >= self.interval {
            let secs = elapsed.as_secs_f64().max(0.000_1);
            let events_per_sec = self.events as f64 / secs;
            let bytes_per_sec = self.bytes as f64 / secs;
            let avg_event = if self.events > 0 {
                self.bytes as f64 / self.events as f64
            } else {
                0.0
            };

            println!(
                "metrics events/s={:.1} bytes/s={:.1} avg_event={}B overruns={}ms missed={}",
                events_per_sec,
                bytes_per_sec,
                avg_event.round() as u64,
                self.overruns.as_millis(),
                self.missed_events
            );

            self.last_report = Instant::now();
            self.events = 0;
            self.bytes = 0;
            self.overruns = Duration::ZERO;
            self.missed_events = 0;
        }
    }
}
