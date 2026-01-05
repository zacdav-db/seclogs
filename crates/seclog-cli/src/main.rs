use clap::{Parser, Subcommand};
use chrono::Utc;
use seclog_core::config::{Config, FormatConfig, SourceConfig};
use seclog_core::event::Event;
use seclog_core::rate::RateController;
use seclog_core::traffic::TrafficModel;
use seclog_core::traits::{EventSource, EventWriter};
use seclog_actors_parquet::write_population;
use seclog_formats_jsonl::JsonlWriter;
use seclog_formats_parquet::ParquetWriter;
use seclog_sources_cloudtrail::{generate_actor_population, CloudTrailGenerator};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread;
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
        #[arg(long, default_value_t = 0)]
        gen_workers: usize,
        #[arg(long, default_value_t = 0)]
        writer_shards: usize,
    },
    Actors {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
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
            gen_workers,
            writer_shards,
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

            let gen_workers = normalize_workers(gen_workers);
            let writer_shards = normalize_writer_shards(writer_shards);
            let queue_depth = gen_workers.saturating_mul(2048).max(1024);

            let running = Arc::new(AtomicBool::new(true));
            let (gen_tx, gen_rx) = sync_channel(queue_depth);
            let source_config = loaded.source.clone();
            let mut gen_handles = Vec::new();
            for worker_id in 0..gen_workers {
                let tx = gen_tx.clone();
                let source = source_config.clone();
                let running = Arc::clone(&running);
                let seed = loaded.seed.map(|value| value.wrapping_add(worker_id as u64));
                let handle = thread::spawn(move || -> WorkerResult {
                    let mut generator = match source {
                        SourceConfig::CloudTrail(config) => {
                            CloudTrailGenerator::from_config(&config, seed)?
                        }
                    };
                    while running.load(Ordering::Relaxed) {
                        if let Some(event) = generator.next_event() {
                            if tx.send(event).is_err() {
                                break;
                            }
                        } else {
                            thread::sleep(Duration::from_millis(5));
                        }
                    }
                    Ok(())
                });
                gen_handles.push(handle);
            }
            drop(gen_tx);

            let counters = WriterCounters::new();
            let (writer_txs, writer_handles) = spawn_writer_shards(
                &loaded.output.dir,
                loaded.output.rotation.target_size_mb,
                loaded.output.rotation.max_age_seconds,
                &loaded.output.format,
                writer_shards,
                queue_depth,
                &counters,
            );
            let tick = Duration::from_millis(100);
            let mut last_tick = Instant::now();
            let mut avg_event_size: f64 = 1024.0;
            let mut total_dispatched = 0_u64;
            let mut last_written_events = 0_u64;
            let mut last_written_bytes = 0_u64;

            let flush_interval = if loaded.output.rotation.max_age_seconds.is_some() {
                Some(Duration::from_secs(1))
            } else if let Some(ms) = loaded.output.rotation.flush_interval_ms {
                Some(Duration::from_millis(ms))
            } else {
                Some(Duration::from_secs(30))
            };
            let mut next_flush = flush_interval.map(|interval| Instant::now() + interval);
            let mut metrics = Metrics::new(Duration::from_millis(metrics_interval_ms));
            let start_time = Instant::now();
            let max_duration = max_seconds.map(Duration::from_secs);
            let mut disconnected = false;

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
                let effective_elapsed = elapsed.min(tick);
                let mut budget =
                    rate_controller.quota(effective_elapsed, multiplier, avg_event_size.round() as u64);

                if let Some(max) = max_events {
                    if total_dispatched >= max {
                        break;
                    }
                    let remaining = max - total_dispatched;
                    if budget > remaining {
                        budget = remaining;
                    }
                }

                if budget == 0 {
                    continue;
                }

                let mut loop_dispatched = 0_u64;

                for _ in 0..budget {
                    let event = match gen_rx.try_recv() {
                        Ok(event) => event,
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            disconnected = true;
                            break;
                        }
                    };

                    dispatch_event(event, &writer_txs, writer_shards)?;
                    total_dispatched += 1;
                    loop_dispatched += 1;
                }

                if disconnected {
                    break;
                }

                let current_events = counters.events.load(Ordering::Relaxed);
                let current_bytes = counters.bytes.load(Ordering::Relaxed);
                let loop_events = current_events.saturating_sub(last_written_events);
                let loop_bytes = current_bytes.saturating_sub(last_written_bytes);
                last_written_events = current_events;
                last_written_bytes = current_bytes;

                if loop_events > 0 {
                    let alpha = 0.1;
                    let per_event = loop_bytes as f64 / loop_events as f64;
                    avg_event_size = (1.0 - alpha) * avg_event_size + alpha * per_event;
                }

                if let (Some(interval), Some(next)) = (flush_interval, next_flush) {
                    if loop_start >= next {
                        for tx in &writer_txs {
                            let _ = tx.send(WriterCommand::Flush);
                        }
                        next_flush = Some(loop_start + interval);
                    }
                }

                let overrun = loop_start.elapsed().saturating_sub(tick);
                let indicate_missed = budget.saturating_sub(loop_dispatched);
                metrics.record(loop_events, loop_bytes, overrun, indicate_missed);
            }

            running.store(false, Ordering::Relaxed);
            drop(gen_rx);
            for tx in &writer_txs {
                let _ = tx.send(WriterCommand::Close);
            }
            drop(writer_txs);

            for handle in gen_handles {
                match handle.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(_) => return Err("generator thread panicked".into()),
                }
            }
            for handle in writer_handles {
                match handle.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(_) => return Err("writer thread panicked".into()),
                }
            }
        }
        Commands::Actors { config, output } => {
            let loaded = Config::from_path(&config)?;
            let population = match &loaded.source {
                SourceConfig::CloudTrail(config) => {
                    generate_actor_population(config, loaded.seed)
                }
            };
            write_population(&output, &population)?;
            println!("actor population written to {}", output.display());
        }
    }

    Ok(())
}

type WorkerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

enum WriterCommand {
    Event(Event),
    Flush,
    Close,
}

struct WriterCounters {
    events: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
}

impl WriterCounters {
    fn new() -> Self {
        Self {
            events: Arc::new(AtomicU64::new(0)),
            bytes: Arc::new(AtomicU64::new(0)),
        }
    }
}

fn normalize_workers(requested: usize) -> usize {
    if requested == 0 {
        thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
            .max(1)
    } else {
        requested.max(1)
    }
}

fn normalize_writer_shards(requested: usize) -> usize {
    if requested == 0 {
        thread::available_parallelism()
            .map(|count| count.get().min(4))
            .unwrap_or(1)
            .max(1)
    } else {
        requested.max(1)
    }
}

fn spawn_writer_shards(
    dir: &str,
    target_size_mb: u64,
    max_age_seconds: Option<u64>,
    format: &FormatConfig,
    shards: usize,
    queue_depth: usize,
    counters: &WriterCounters,
) -> (
    Vec<SyncSender<WriterCommand>>,
    Vec<thread::JoinHandle<WorkerResult>>,
) {
    let mut senders = Vec::with_capacity(shards);
    let mut handles = Vec::with_capacity(shards);
    for _ in 0..shards {
        let (tx, rx): (SyncSender<WriterCommand>, Receiver<WriterCommand>) =
            sync_channel(queue_depth);
        let format = format.clone();
        let dir = dir.to_string();
        let events_counter = Arc::clone(&counters.events);
        let bytes_counter = Arc::clone(&counters.bytes);
        let handle = thread::spawn(move || -> WorkerResult {
            let mut writer: Box<dyn EventWriter> = match format {
                FormatConfig::Jsonl(_) => Box::new(JsonlWriter::new(
                    &dir,
                    target_size_mb,
                    max_age_seconds,
                )?),
                FormatConfig::Parquet(_) => Box::new(ParquetWriter::new(
                    &dir,
                    target_size_mb,
                    max_age_seconds,
                )?),
            };
            while let Ok(command) = rx.recv() {
                match command {
                    WriterCommand::Event(event) => {
                        let bytes = writer.write_event(&event)?;
                        events_counter.fetch_add(1, Ordering::Relaxed);
                        bytes_counter.fetch_add(bytes, Ordering::Relaxed);
                    }
                    WriterCommand::Flush => {
                        writer.flush()?;
                    }
                    WriterCommand::Close => {
                        writer.close()?;
                        break;
                    }
                }
            }
            Ok(())
        });
        senders.push(tx);
        handles.push(handle);
    }

    (senders, handles)
}

fn dispatch_event(
    event: Event,
    writers: &[SyncSender<WriterCommand>],
    shards: usize,
) -> Result<(), std::sync::mpsc::SendError<WriterCommand>> {
    if writers.is_empty() {
        return Ok(());
    }
    let idx = writer_index_for_event(&event, shards);
    writers[idx].send(WriterCommand::Event(event))
}

fn writer_index_for_event(event: &Event, shards: usize) -> usize {
    if shards <= 1 {
        return 0;
    }
    let account_id = event
        .envelope
        .tenant_id
        .as_deref()
        .unwrap_or("000000000000");
    let region = event
        .payload
        .get("aws_region")
        .and_then(|value| value.as_str())
        .unwrap_or("global");

    let mut hasher = DefaultHasher::new();
    account_id.hash(&mut hasher);
    region.hash(&mut hasher);
    (hasher.finish() as usize) % shards
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
