use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use seclog::actors_parquet::write_population;
use seclog::core::actors::generate_population;
use seclog::core::config::{
    Config, FileOutputConfig, FormatConfig, MultiSourceConfig, OutputConfig, PopulationConfig,
    SourceConfig, ZerobusOutputConfig,
};
use seclog::core::event::Event;
use seclog::core::traits::{EventSource, EventWriter};
use seclog::formats::json::JsonlWriter;
use seclog::formats::parquet::ParquetWriter;
use seclog::formats::zerobus::ZerobusWriter;
use seclog::sources::cloudtrail::CloudTrailGenerator;
use seclog::sources::composite::CompositeEventSource;
use seclog::sources::databricks::DatabricksAuditGenerator;
use seclog::sources::okta::OktaSystemLogGenerator;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
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
                loaded
                    .output
                    .override_file_dir(dir.to_string_lossy().to_string())?;
            }

            if dry_run {
                println!("config loaded: {loaded:#?}");
                return Ok(());
            }

            let requested_gen_workers = gen_workers;
            let requested_writer_shards = writer_shards;
            let gen_workers = normalize_workers(gen_workers);
            let writer_shards = normalize_writer_shards(writer_shards);
            if requested_gen_workers > 1 {
                eprintln!(
                    "warning: actor-driven mode uses a single generator for ordered output; forcing gen-workers=1"
                );
            }
            let queue_depth = 1024;

            let start_time = Instant::now();
            let max_duration = max_seconds.map(Duration::from_secs);
            let start_sim_time = parse_start_time(loaded.traffic.start_time.as_deref())?;
            let time_scale = loaded.traffic.time_scale.unwrap_or(1.0);
            let time_scale = if time_scale <= 0.0 {
                None
            } else {
                Some(time_scale)
            };

            match &loaded.output {
                OutputConfig::File(output) => {
                    if let SourceConfig::Multi(config) = &loaded.source {
                        run_multi_file_generation(
                            config,
                            output,
                            loaded.seed,
                            start_sim_time,
                            time_scale,
                            max_events,
                            max_duration,
                            writer_shards,
                            queue_depth,
                            Duration::from_millis(metrics_interval_ms),
                        )?;
                    } else {
                        let generator =
                            build_event_source(&loaded.source, loaded.seed, start_sim_time)?;
                        run_file_generation(
                            generator,
                            output,
                            time_scale,
                            start_sim_time,
                            start_time,
                            max_events,
                            max_duration,
                            writer_shards,
                            queue_depth,
                            Duration::from_millis(metrics_interval_ms),
                        )?;
                    }
                }
                OutputConfig::Zerobus(output) => {
                    if requested_writer_shards > 1 {
                        eprintln!(
                            "warning: zerobus output opens one stream per source; forcing writer-shards=1"
                        );
                    }
                    validate_zerobus_table_routes(&loaded.source, output)?;
                    let generator =
                        build_event_source(&loaded.source, loaded.seed, start_sim_time)?;
                    run_zerobus_generation(
                        generator,
                        output,
                        time_scale,
                        start_sim_time,
                        start_time,
                        max_events,
                        max_duration,
                        Duration::from_millis(metrics_interval_ms),
                    )?;
                }
            }
        }
        Commands::Actors { config, output } => {
            let loaded = PopulationConfig::from_path(&config)?;
            let population = generate_population(&loaded)?;
            write_population(&output, &population)?;
            println!("actor population written to {}", output.display());
        }
    }

    Ok(())
}

fn build_event_source(
    config: &SourceConfig,
    seed: Option<u64>,
    start_sim_time: DateTime<Utc>,
) -> Result<Box<dyn EventSource>, Box<dyn std::error::Error>> {
    match config {
        SourceConfig::CloudTrail(config) => Ok(Box::new(CloudTrailGenerator::from_config(
            config,
            seed,
            start_sim_time,
        )?)),
        SourceConfig::DatabricksAudit(config) => Ok(Box::new(
            DatabricksAuditGenerator::from_config(config, start_sim_time)?,
        )),
        SourceConfig::OktaSystemLog(config) => Ok(Box::new(OktaSystemLogGenerator::from_config(
            config,
            start_sim_time,
        )?)),
        SourceConfig::Multi(config) => {
            if config.sources.is_empty() {
                return Err("multi source requires at least one child source".into());
            }
            let mut sources = Vec::with_capacity(config.sources.len());
            for (idx, source) in config.sources.iter().enumerate() {
                let source =
                    inherit_identity_registry(source, config.identity_registry_path.as_deref());
                let child_seed = seed.map(|seed| seed.wrapping_add(idx as u64));
                sources.push(build_event_source(&source, child_seed, start_sim_time)?);
            }
            Ok(Box::new(CompositeEventSource::new(sources)))
        }
    }
}

fn inherit_identity_registry(config: &SourceConfig, path: Option<&str>) -> SourceConfig {
    let mut inherited = config.clone();
    let Some(path) = path else {
        return inherited;
    };

    match &mut inherited {
        SourceConfig::CloudTrail(config) => {
            if config.actor_population_path.is_none() && config.identity_registry_path.is_none() {
                config.identity_registry_path = Some(path.to_string());
            }
        }
        SourceConfig::DatabricksAudit(config) => {
            if config.identity_registry_path.trim().is_empty() {
                config.identity_registry_path = path.to_string();
            }
        }
        SourceConfig::OktaSystemLog(config) => {
            if config.identity_registry_path.trim().is_empty() {
                config.identity_registry_path = path.to_string();
            }
        }
        SourceConfig::Multi(config) => {
            if config.identity_registry_path.is_none() {
                config.identity_registry_path = Some(path.to_string());
            }
        }
    }

    inherited
}

#[allow(clippy::too_many_arguments)]
fn run_file_generation(
    mut generator: Box<dyn EventSource>,
    output: &FileOutputConfig,
    time_scale: Option<f64>,
    start_sim_time: DateTime<Utc>,
    start_time: Instant,
    max_events: Option<u64>,
    max_duration: Option<Duration>,
    writer_shards: usize,
    queue_depth: usize,
    metrics_interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let counters = WriterCounters::new();
    let (writer_txs, writer_handles) =
        spawn_writer_shards(output, writer_shards, queue_depth, &counters);
    let flush_interval = Some(Duration::from_secs(1));
    let mut next_flush = flush_interval.map(|interval| Instant::now() + interval);
    let mut metrics = Metrics::new(metrics_interval);
    let mut total_dispatched = 0_u64;
    let mut last_written_events = 0_u64;
    let mut last_written_bytes = 0_u64;
    let mut last_sim_time = start_sim_time;
    let mut last_wall = Instant::now();

    loop {
        let loop_start = Instant::now();
        if let Some(limit) = max_duration {
            if loop_start.duration_since(start_time) >= limit {
                break;
            }
        }
        if let Some(max) = max_events {
            if total_dispatched >= max {
                break;
            }
        }

        let Some(event) = generator.next_event() else {
            break;
        };

        if let Some(event_time) = parse_event_time(&event) {
            if let Some(scale) = time_scale {
                throttle_to_sim_time(event_time, last_sim_time, scale, &mut last_wall);
            }
            last_sim_time = event_time;
        }

        dispatch_event(event, &writer_txs, writer_shards)?;
        total_dispatched += 1;

        let current_events = counters.events.load(Ordering::Relaxed);
        let current_bytes = counters.bytes.load(Ordering::Relaxed);
        let loop_events = current_events.saturating_sub(last_written_events);
        let loop_bytes = current_bytes.saturating_sub(last_written_bytes);
        last_written_events = current_events;
        last_written_bytes = current_bytes;

        if let (Some(interval), Some(next)) = (flush_interval, next_flush) {
            if loop_start >= next {
                for tx in &writer_txs {
                    let _ = tx.send(WriterCommand::Flush);
                }
                next_flush = Some(loop_start + interval);
            }
        }

        metrics.record(loop_events, loop_bytes, Duration::ZERO, 0);
    }

    for tx in &writer_txs {
        let _ = tx.send(WriterCommand::Close);
    }
    drop(writer_txs);

    for handle in writer_handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(format!("writer thread failed: {err}").into()),
            Err(_) => return Err("writer thread panicked".into()),
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_multi_file_generation(
    config: &MultiSourceConfig,
    default_output: &FileOutputConfig,
    seed: Option<u64>,
    start_sim_time: DateTime<Utc>,
    time_scale: Option<f64>,
    max_events: Option<u64>,
    max_duration: Option<Duration>,
    writer_shards: usize,
    queue_depth: usize,
    metrics_interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.sources.is_empty() {
        return Err("multi source requires at least one child source".into());
    }

    let source_config = SourceConfig::Multi(config.clone());
    let mut generator = build_event_source(&source_config, seed, start_sim_time)?;
    let mut writers = RoutedWriters::new(config, default_output, writer_shards, queue_depth)?;
    let flush_interval = Some(Duration::from_secs(1));
    let mut next_flush = flush_interval.map(|interval| Instant::now() + interval);
    let mut metrics = Metrics::new(metrics_interval);
    let start_time = Instant::now();
    let mut last_sim_time = start_sim_time;
    let mut last_wall = Instant::now();
    let mut total_dispatched = 0_u64;
    let mut last_written_events = 0_u64;
    let mut last_written_bytes = 0_u64;

    loop {
        let loop_start = Instant::now();
        if let Some(limit) = max_duration {
            if loop_start.duration_since(start_time) >= limit {
                break;
            }
        }
        if let Some(max) = max_events {
            if total_dispatched >= max {
                break;
            }
        }

        let Some(event) = generator.next_event() else {
            break;
        };

        if let Some(event_time) = parse_event_time(&event) {
            if let Some(scale) = time_scale {
                throttle_to_sim_time(event_time, last_sim_time, scale, &mut last_wall);
            }
            last_sim_time = event_time;
        }

        writers.dispatch(event)?;
        total_dispatched += 1;

        let current_events = writers.counters.events.load(Ordering::Relaxed);
        let current_bytes = writers.counters.bytes.load(Ordering::Relaxed);
        let loop_events = current_events.saturating_sub(last_written_events);
        let loop_bytes = current_bytes.saturating_sub(last_written_bytes);
        last_written_events = current_events;
        last_written_bytes = current_bytes;

        if let (Some(interval), Some(next)) = (flush_interval, next_flush) {
            if loop_start >= next {
                writers.flush_all();
                next_flush = Some(loop_start + interval);
            }
        }

        metrics.record(loop_events, loop_bytes, Duration::ZERO, 0);
    }

    writers.close()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_zerobus_generation(
    mut generator: Box<dyn EventSource>,
    output: &ZerobusOutputConfig,
    time_scale: Option<f64>,
    start_sim_time: DateTime<Utc>,
    start_time: Instant,
    max_events: Option<u64>,
    max_duration: Option<Duration>,
    metrics_interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = ZerobusWriter::new(output)?;
    let flush_interval = Some(Duration::from_millis(output.flush_interval_ms.max(1)));
    let mut next_flush = flush_interval.map(|interval| Instant::now() + interval);
    let mut metrics = Metrics::new(metrics_interval);
    let mut total_dispatched = 0_u64;
    let mut loop_bytes = 0_u64;
    let mut last_sim_time = start_sim_time;
    let mut last_wall = Instant::now();

    loop {
        let loop_start = Instant::now();
        if let Some(limit) = max_duration {
            if loop_start.duration_since(start_time) >= limit {
                break;
            }
        }
        if let Some(max) = max_events {
            if total_dispatched >= max {
                break;
            }
        }

        let Some(event) = generator.next_event() else {
            break;
        };

        if let Some(event_time) = parse_event_time(&event) {
            if let Some(scale) = time_scale {
                throttle_to_sim_time(event_time, last_sim_time, scale, &mut last_wall);
            }
            last_sim_time = event_time;
        }

        loop_bytes += writer.write_event(&event)?;
        total_dispatched += 1;

        if let (Some(interval), Some(next)) = (flush_interval, next_flush) {
            if loop_start >= next {
                writer.flush()?;
                next_flush = Some(loop_start + interval);
            }
        }

        metrics.record(1, loop_bytes, Duration::ZERO, 0);
        loop_bytes = 0;
    }

    writer.close()?;
    Ok(())
}

struct RoutedWriters {
    routes: HashMap<String, WriterRoute>,
    handles: Vec<thread::JoinHandle<WorkerResult>>,
    counters: WriterCounters,
}

struct WriterRoute {
    senders: Vec<SyncSender<WriterCommand>>,
    shards: usize,
}

impl RoutedWriters {
    fn new(
        config: &MultiSourceConfig,
        default_output: &FileOutputConfig,
        writer_shards: usize,
        queue_depth: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let counters = WriterCounters::new();
        let mut routes = HashMap::new();
        let mut handles = Vec::new();
        for source in &config.sources {
            for key in source_output_keys(source) {
                if routes.contains_key(&key) {
                    continue;
                }
                let output = config
                    .outputs
                    .as_ref()
                    .and_then(|outputs| outputs.get(&key))
                    .unwrap_or(default_output);
                let (senders, route_handles) =
                    spawn_writer_shards(output, writer_shards, queue_depth, &counters);
                handles.extend(route_handles);
                routes.insert(
                    key,
                    WriterRoute {
                        senders,
                        shards: writer_shards,
                    },
                );
            }
        }

        Ok(Self {
            routes,
            handles,
            counters,
        })
    }

    fn dispatch(&self, event: Event) -> Result<(), Box<dyn std::error::Error>> {
        let source = event.envelope.source.clone();
        let route = self
            .routes
            .get(&source)
            .ok_or_else(|| format!("no output route configured for source {source}"))?;
        dispatch_event(event, &route.senders, route.shards)
    }

    fn flush_all(&self) {
        for route in self.routes.values() {
            for tx in &route.senders {
                let _ = tx.send(WriterCommand::Flush);
            }
        }
    }

    fn close(self) -> Result<(), Box<dyn std::error::Error>> {
        for route in self.routes.values() {
            for tx in &route.senders {
                let _ = tx.send(WriterCommand::Close);
            }
        }
        drop(self.routes);

        for handle in self.handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(format!("writer thread failed: {err}").into()),
                Err(_) => return Err("writer thread panicked".into()),
            }
        }
        Ok(())
    }
}

fn source_output_keys(config: &SourceConfig) -> Vec<String> {
    match config {
        SourceConfig::CloudTrail(_) => vec!["cloudtrail".to_string()],
        SourceConfig::DatabricksAudit(_) => vec!["databricks_audit".to_string()],
        SourceConfig::OktaSystemLog(_) => vec!["okta_system_log".to_string()],
        SourceConfig::Multi(config) => config.sources.iter().flat_map(source_output_keys).collect(),
    }
}

fn validate_zerobus_table_routes(
    config: &SourceConfig,
    output: &ZerobusOutputConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    for source in source_output_keys(config) {
        if !output.tables.contains_key(&source) {
            return Err(format!("no zerobus table configured for source {source}").into());
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

fn parse_start_time(value: Option<&str>) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    match value {
        Some(raw) => {
            let parsed = DateTime::parse_from_rfc3339(raw)?;
            Ok(parsed.with_timezone(&Utc))
        }
        None => Ok(Utc::now()),
    }
}

fn parse_event_time(event: &Event) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&event.envelope.timestamp)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn throttle_to_sim_time(
    current: DateTime<Utc>,
    previous: DateTime<Utc>,
    scale: f64,
    last_wall: &mut Instant,
) {
    if scale <= 0.0 {
        return;
    }
    if current <= previous {
        return;
    }
    let sim_delta = current - previous;
    let sim_secs = sim_delta.num_milliseconds().max(0) as f64 / 1000.0;
    let target = Duration::from_secs_f64(sim_secs / scale);
    let elapsed = last_wall.elapsed();
    if target > elapsed {
        std::thread::sleep(target - elapsed);
    }
    *last_wall = Instant::now();
}

fn spawn_writer_shards(
    output: &FileOutputConfig,
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
        let format = output.format.clone();
        let dir = output.dir.clone();
        let target_size_mb = output.files.target_size_mb;
        let max_age_seconds = Some(output.files.max_age_seconds);
        let events_counter = Arc::clone(&counters.events);
        let bytes_counter = Arc::clone(&counters.bytes);
        let handle = thread::spawn(move || -> WorkerResult {
            let mut writer: Box<dyn EventWriter> = match format {
                FormatConfig::Jsonl(options) => Box::new(JsonlWriter::new(
                    &dir,
                    target_size_mb,
                    max_age_seconds,
                    options.compression.as_deref(),
                )?),
                FormatConfig::Parquet(_) => {
                    Box::new(ParquetWriter::new(&dir, target_size_mb, max_age_seconds)?)
                }
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
) -> Result<(), Box<dyn std::error::Error>> {
    if writers.is_empty() {
        return Ok(());
    }
    let idx = writer_index_for_event(&event, shards);
    writers[idx]
        .send(WriterCommand::Event(event))
        .map_err(|_| "writer queue is closed".into())
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
        .get("awsRegion")
        .or_else(|| event.payload.get("aws_region"))
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
