use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use seclog::actors_parquet::write_population;
use seclog::api::build_event_source;
use seclog::core::actors::generate_population;
use seclog::core::config::{
    Config, DatabricksVolumeOutputConfig, FileOutputConfig, FormatConfig, MultiSourceConfig,
    OutputConfig, PopulationConfig, SourceConfig, ZerobusOutputConfig,
};
use seclog::core::event::Event;
use seclog::core::identity::{Identity, IdentityRegistry};
use seclog::core::traits::{EventSource, EventWriter};
use seclog::formats::databricks_volume::DatabricksVolumeWriter;
use seclog::formats::json::JsonlWriter;
use seclog::formats::parquet::ParquetWriter;
use seclog::formats::zerobus::ZerobusWriter;
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const ACTOR_POPULATION_SOURCE: &str = "actor_population";

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
        #[arg(long)]
        until_time: Option<String>,
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
            until_time,
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
            let until_sim_time = parse_optional_time(
                until_time
                    .as_deref()
                    .or(loaded.traffic.until_time.as_deref()),
            )?;
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
                            until_sim_time,
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
                            until_sim_time,
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
                        &loaded.source,
                        output,
                        time_scale,
                        start_sim_time,
                        start_time,
                        until_sim_time,
                        max_events,
                        max_duration,
                        Duration::from_millis(metrics_interval_ms),
                    )?;
                }
                OutputConfig::DatabricksVolume(output) => {
                    if requested_writer_shards > 1 {
                        eprintln!(
                            "warning: databricks_volume output uploads rotated files from one writer; forcing writer-shards=1"
                        );
                    }
                    let generator =
                        build_event_source(&loaded.source, loaded.seed, start_sim_time)?;
                    run_databricks_volume_generation(
                        generator,
                        output,
                        time_scale,
                        start_sim_time,
                        start_time,
                        until_sim_time,
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

fn identity_registry_from_population_config_path(
    path: &str,
) -> Result<IdentityRegistry, Box<dyn std::error::Error>> {
    let config = PopulationConfig::from_path(path)?;
    let population = generate_population(&config)?;
    Ok(IdentityRegistry::from_population(
        "generated_identity_registry",
        &population,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn run_file_generation(
    mut generator: Box<dyn EventSource>,
    output: &FileOutputConfig,
    time_scale: Option<f64>,
    start_sim_time: DateTime<Utc>,
    start_time: Instant,
    until_sim_time: Option<DateTime<Utc>>,
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
    let mut metrics = Metrics::new(metrics_interval, start_sim_time);
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

        let event_time = parse_event_time(&event);
        let metric_event_time = event_time.clone();
        if should_stop_at_until(event_time, until_sim_time) {
            break;
        }
        if let Some(event_time) = event_time {
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

        metrics.record(
            loop_events,
            loop_bytes,
            Duration::ZERO,
            0,
            metric_event_time,
        );
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
    until_sim_time: Option<DateTime<Utc>>,
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
    let mut metrics = Metrics::new(metrics_interval, start_sim_time);
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

        let event_time = parse_event_time(&event);
        let metric_event_time = event_time.clone();
        if should_stop_at_until(event_time, until_sim_time) {
            break;
        }
        if let Some(event_time) = event_time {
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

        metrics.record(
            loop_events,
            loop_bytes,
            Duration::ZERO,
            0,
            metric_event_time,
        );
    }

    writers.close()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_zerobus_generation(
    mut generator: Box<dyn EventSource>,
    source_config: &SourceConfig,
    output: &ZerobusOutputConfig,
    time_scale: Option<f64>,
    start_sim_time: DateTime<Utc>,
    start_time: Instant,
    until_sim_time: Option<DateTime<Utc>>,
    max_events: Option<u64>,
    max_duration: Option<Duration>,
    metrics_interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = ZerobusWriter::new(output)?;
    persist_zerobus_actor_population_if_configured(source_config, output, &mut writer)?;
    let flush_interval = Some(Duration::from_millis(output.flush_interval_ms.max(1)));
    let mut next_flush = flush_interval.map(|interval| Instant::now() + interval);
    let mut metrics = Metrics::new(metrics_interval, start_sim_time);
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

        let event_time = parse_event_time(&event);
        let metric_event_time = event_time.clone();
        if should_stop_at_until(event_time, until_sim_time) {
            break;
        }
        if let Some(event_time) = event_time {
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

        metrics.record(1, loop_bytes, Duration::ZERO, 0, metric_event_time);
        loop_bytes = 0;
    }

    writer.close()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_databricks_volume_generation(
    mut generator: Box<dyn EventSource>,
    output: &DatabricksVolumeOutputConfig,
    time_scale: Option<f64>,
    start_sim_time: DateTime<Utc>,
    start_time: Instant,
    until_sim_time: Option<DateTime<Utc>>,
    max_events: Option<u64>,
    max_duration: Option<Duration>,
    metrics_interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = DatabricksVolumeWriter::new(output)?;
    let flush_interval = Some(Duration::from_millis(output.flush_interval_ms.max(1)));
    let mut next_flush = flush_interval.map(|interval| Instant::now() + interval);
    let mut metrics = Metrics::new(metrics_interval, start_sim_time);
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

        let event_time = parse_event_time(&event);
        let metric_event_time = event_time.clone();
        if should_stop_at_until(event_time, until_sim_time) {
            break;
        }
        if let Some(event_time) = event_time {
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

        metrics.record(1, loop_bytes, Duration::ZERO, 0, metric_event_time);
        loop_bytes = 0;
    }

    writer.close()?;
    Ok(())
}

fn persist_zerobus_actor_population_if_configured(
    source_config: &SourceConfig,
    output: &ZerobusOutputConfig,
    writer: &mut ZerobusWriter,
) -> Result<(), Box<dyn std::error::Error>> {
    if !output.tables.contains_key(ACTOR_POPULATION_SOURCE) {
        return Ok(());
    }

    let registry = identity_registry_for_actor_population(source_config)?.ok_or_else(|| {
        format!(
            "zerobus table {ACTOR_POPULATION_SOURCE} requires an identity_registry_path, population_config_path, or population_config source"
        )
    })?;
    let generated_at = Utc::now();

    for identity in registry.identities() {
        let row =
            identity_population_row_json(registry.name(), identity, writer.run_id(), generated_at)?;
        writer.write_json_record(ACTOR_POPULATION_SOURCE, row)?;
    }
    writer.flush()?;
    Ok(())
}

fn identity_registry_for_actor_population(
    config: &SourceConfig,
) -> Result<Option<IdentityRegistry>, Box<dyn std::error::Error>> {
    let population_config = population_config_source(config)?;
    let registry_path = identity_registry_path(config)?;
    match (population_config, registry_path) {
        (Some(_), Some(_)) => Err(format!(
            "zerobus table {ACTOR_POPULATION_SOURCE} cannot use both identity_registry_path and population_config"
        )
        .into()),
        (Some(PopulationConfigSource::Path(population_path)), None) => Ok(Some(
            identity_registry_from_population_config_path(&population_path)?,
        )),
        (Some(PopulationConfigSource::Inline(population_config)), None) => Ok(Some(
            identity_registry_from_population_config(&population_config)?,
        )),
        (None, Some(registry_path)) => Ok(Some(IdentityRegistry::from_path(&registry_path)?)),
        (None, None) => Ok(None),
    }
}

enum PopulationConfigSource {
    Path(String),
    Inline(PopulationConfig),
}

fn identity_registry_path(
    config: &SourceConfig,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut paths = BTreeSet::new();
    collect_identity_registry_paths(config, None, &mut paths)?;
    match paths.len() {
        0 => Ok(None),
        1 => Ok(paths.into_iter().next()),
        _ => Err(format!(
            "zerobus table {ACTOR_POPULATION_SOURCE} requires a single shared identity_registry_path, found: {}",
            paths.into_iter().collect::<Vec<_>>().join(", ")
        )
        .into()),
    }
}

fn population_config_path(
    config: &SourceConfig,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut paths = BTreeSet::new();
    collect_population_config_paths(config, &mut paths)?;
    match paths.len() {
        0 => Ok(None),
        1 => Ok(paths.into_iter().next()),
        _ => Err(format!(
            "zerobus table {ACTOR_POPULATION_SOURCE} requires a single shared population_config_path, found: {}",
            paths.into_iter().collect::<Vec<_>>().join(", ")
        )
        .into()),
    }
}

fn population_config_source(
    config: &SourceConfig,
) -> Result<Option<PopulationConfigSource>, Box<dyn std::error::Error>> {
    let mut paths = BTreeSet::new();
    let mut inline_configs = Vec::new();
    collect_population_configs(config, &mut paths, &mut inline_configs)?;

    let configured_count = paths.len() + inline_configs.len();
    match configured_count {
        0 => Ok(None),
        1 if paths.len() == 1 => Ok(paths.into_iter().next().map(PopulationConfigSource::Path)),
        1 => Ok(inline_configs.pop().map(PopulationConfigSource::Inline)),
        _ => Err(format!(
            "zerobus table {ACTOR_POPULATION_SOURCE} requires a single shared population_config, found {} path(s) and {} inline config(s)",
            paths.len(),
            inline_configs.len()
        )
        .into()),
    }
}

fn collect_identity_registry_paths(
    config: &SourceConfig,
    inherited_path: Option<&str>,
    paths: &mut BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    match config {
        SourceConfig::CloudTrail(config) => {
            insert_optional_path(
                paths,
                config
                    .identity_registry_path
                    .as_deref()
                    .and_then(non_empty_str)
                    .or(inherited_path),
            );
        }
        SourceConfig::DatabricksAudit(config) => {
            insert_optional_path(
                paths,
                non_empty_str(&config.identity_registry_path).or(inherited_path),
            );
        }
        SourceConfig::OktaSystemLog(config) => {
            insert_optional_path(
                paths,
                non_empty_str(&config.identity_registry_path).or(inherited_path),
            );
        }
        SourceConfig::Multi(config) => {
            let next_inherited = config
                .identity_registry_path
                .as_deref()
                .and_then(non_empty_str)
                .or(inherited_path);
            for source in &config.sources {
                collect_identity_registry_paths(source, next_inherited, paths)?;
            }
        }
    }
    Ok(())
}

fn collect_population_config_paths(
    config: &SourceConfig,
    paths: &mut BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let SourceConfig::Multi(config) = config {
        insert_optional_path(paths, config.population_config_path.as_deref());
        for source in &config.sources {
            collect_population_config_paths(source, paths)?;
        }
    }
    Ok(())
}

fn collect_population_configs(
    config: &SourceConfig,
    paths: &mut BTreeSet<String>,
    inline_configs: &mut Vec<PopulationConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let SourceConfig::Multi(config) = config {
        insert_optional_path(paths, config.population_config_path.as_deref());
        if let Some(population_config) = &config.population_config {
            inline_configs.push(population_config.clone());
        }
        for source in &config.sources {
            collect_population_configs(source, paths, inline_configs)?;
        }
    }
    Ok(())
}

fn insert_optional_path(paths: &mut BTreeSet<String>, value: Option<&str>) {
    if let Some(value) = value.and_then(non_empty_str) {
        paths.insert(value.to_string());
    }
}

fn non_empty_str(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn identity_population_row_json(
    registry_name: &str,
    identity: &Identity,
    run_id: &str,
    generated_at: DateTime<Utc>,
) -> Result<String, Box<dyn std::error::Error>> {
    let identity_json = serde_json::to_string(identity)?;
    let row = json!({
        "time": generated_at.timestamp_micros(),
        "registry_name": registry_name,
        "actor_id": &identity.actor_id,
        "actor_kind": if identity.service_account { "service" } else { "human" },
        "email": &identity.email,
        "employee_id": &identity.employee_id,
        "display_name": &identity.display_name,
        "role_persona": &identity.role_persona,
        "department": &identity.department,
        "home_location": &identity.home_location,
        "normal_countries_regions_json": serde_json::to_string(&identity.normal_countries_regions)?,
        "okta_user_id": &identity.okta_user_id,
        "databricks_username": &identity.databricks_username,
        "service_account": identity.service_account,
        "rate_per_hour": identity.rate_per_hour,
        "active_start_hour": identity.active_start_hour,
        "active_hours": identity.active_hours,
        "timezone_offset": identity.timezone_offset,
        "weekend_active": identity.weekend_active,
        "service_pattern": &identity.service_pattern,
        "tags_json": serde_json::to_string(&identity.tags)?,
        "aws_principals_json": serde_json::to_string(&identity.aws_principals)?,
        "identity_json": identity_json,
        "run_id": run_id,
        "generated_at": generated_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    Ok(serde_json::to_string(&row)?)
}

fn identity_registry_from_population_config(
    config: &PopulationConfig,
) -> Result<IdentityRegistry, Box<dyn std::error::Error>> {
    let population = generate_population(config)?;
    Ok(IdentityRegistry::from_population(
        "generated_identity_registry",
        &population,
    )?)
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

fn parse_optional_time(
    value: Option<&str>,
) -> Result<Option<DateTime<Utc>>, Box<dyn std::error::Error>> {
    value
        .map(|raw| DateTime::parse_from_rfc3339(raw).map(|parsed| parsed.with_timezone(&Utc)))
        .transpose()
        .map_err(Into::into)
}

fn parse_event_time(event: &Event) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&event.envelope.timestamp)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn should_stop_at_until(
    event_time: Option<DateTime<Utc>>,
    until_time: Option<DateTime<Utc>>,
) -> bool {
    matches!((event_time, until_time), (Some(event_time), Some(until_time)) if event_time > until_time)
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
    started_at: Instant,
    last_report: Instant,
    start_sim_time: DateTime<Utc>,
    sim_high_water: DateTime<Utc>,
    events: u64,
    bytes: u64,
    overruns: Duration,
    missed_events: u64,
}

impl Metrics {
    fn new(interval: Duration, start_sim_time: DateTime<Utc>) -> Self {
        let now = Instant::now();
        Self {
            interval,
            started_at: now,
            last_report: now,
            start_sim_time,
            sim_high_water: start_sim_time,
            events: 0,
            bytes: 0,
            overruns: Duration::ZERO,
            missed_events: 0,
        }
    }

    fn record(
        &mut self,
        events: u64,
        bytes: u64,
        overrun: Duration,
        missed: u64,
        event_time: Option<DateTime<Utc>>,
    ) {
        self.events += events;
        self.bytes += bytes;
        self.overruns += overrun;
        self.missed_events += missed;
        if let Some(event_time) = event_time {
            if event_time > self.sim_high_water {
                self.sim_high_water = event_time;
            }
        }

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
            let sim_elapsed_ms = (self.sim_high_water - self.start_sim_time)
                .num_milliseconds()
                .max(0);

            println!(
                "metrics events/s={:.1} bytes/s={:.1} avg_event={}B sim_high_water={} sim_elapsed={}s wall_elapsed={:.1}s overruns={}ms missed={}",
                events_per_sec,
                bytes_per_sec,
                avg_event.round() as u64,
                self.sim_high_water.to_rfc3339_opts(SecondsFormat::Millis, true),
                sim_elapsed_ms / 1000,
                self.started_at.elapsed().as_secs_f64(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use seclog::core::config::{CloudTrailSourceConfig, MultiSourceConfig};
    use seclog::core::identity::AwsPrincipal;
    use serde_json::Value;

    #[test]
    fn identity_population_row_has_required_timestamp_column() {
        let generated_at = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let row = identity_population_row_json(
            "registry-1",
            &identity("user-001", false),
            "run-1",
            generated_at,
        )
        .unwrap();
        let row: Value = serde_json::from_str(&row).unwrap();

        assert_eq!(row["time"], 1767225600000000_i64);
        assert_eq!(row["registry_name"], "registry-1");
        assert_eq!(row["actor_id"], "user-001");
        assert_eq!(row["actor_kind"], "human");
        assert_eq!(row["generated_at"], "2026-01-01T00:00:00.000Z");
        assert_eq!(
            serde_json::from_str::<Value>(row["identity_json"].as_str().unwrap()).unwrap()
                ["actor_id"],
            "user-001"
        );
    }

    #[test]
    fn multi_source_population_uses_inherited_registry_path() {
        let config = SourceConfig::Multi(MultiSourceConfig {
            identity_registry_path: Some("./examples/identity_registry.toml".to_string()),
            population_config_path: None,
            population_config: None,
            sources: vec![
                SourceConfig::CloudTrail(cloudtrail(None)),
                SourceConfig::CloudTrail(cloudtrail(None)),
            ],
            outputs: None,
        });

        assert_eq!(
            identity_registry_path(&config).unwrap().as_deref(),
            Some("./examples/identity_registry.toml")
        );
    }

    #[test]
    fn multi_source_population_rejects_multiple_registry_paths() {
        let config = SourceConfig::Multi(MultiSourceConfig {
            identity_registry_path: None,
            population_config_path: None,
            population_config: None,
            sources: vec![
                SourceConfig::CloudTrail(cloudtrail(Some("./registry-a.toml"))),
                SourceConfig::CloudTrail(cloudtrail(Some("./registry-b.toml"))),
            ],
            outputs: None,
        });

        let err = identity_registry_path(&config).unwrap_err().to_string();
        assert!(err.contains("requires a single shared identity_registry_path"));
        assert!(err.contains("./registry-a.toml"));
        assert!(err.contains("./registry-b.toml"));
    }

    #[test]
    fn multi_source_population_uses_population_config_path() {
        let config = SourceConfig::Multi(MultiSourceConfig {
            identity_registry_path: None,
            population_config_path: Some("./examples/actors.toml".to_string()),
            population_config: None,
            sources: vec![SourceConfig::CloudTrail(cloudtrail(None))],
            outputs: None,
        });

        assert_eq!(
            population_config_path(&config).unwrap().as_deref(),
            Some("./examples/actors.toml")
        );
    }

    #[test]
    fn actor_population_rejects_registry_and_population_config_together() {
        let config = SourceConfig::Multi(MultiSourceConfig {
            identity_registry_path: Some("./examples/identity_registry.toml".to_string()),
            population_config_path: Some("./examples/actors.toml".to_string()),
            population_config: None,
            sources: vec![SourceConfig::CloudTrail(cloudtrail(None))],
            outputs: None,
        });

        let err = identity_registry_for_actor_population(&config)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot use both identity_registry_path and population_config"));
    }

    #[test]
    fn generated_population_rejects_child_registry_paths() {
        let config = SourceConfig::Multi(MultiSourceConfig {
            identity_registry_path: None,
            population_config_path: Some("./examples/actors.toml".to_string()),
            population_config: None,
            sources: vec![SourceConfig::CloudTrail(cloudtrail(Some(
                "./examples/identity_registry.toml",
            )))],
            outputs: None,
        });

        let err = match build_event_source(&config, Some(1), Utc::now()) {
            Ok(_) => panic!("expected generated population conflict"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("cannot also set child identity_registry_path"));
    }

    fn cloudtrail(identity_registry_path: Option<&str>) -> CloudTrailSourceConfig {
        CloudTrailSourceConfig {
            curated: true,
            actor_population_path: None,
            identity_registry_path: identity_registry_path.map(str::to_string),
            baseline_source_ips: None,
            regions: None,
            region_distribution: None,
        }
    }

    fn identity(actor_id: &str, service_account: bool) -> Identity {
        Identity {
            actor_id: actor_id.to_string(),
            email: format!("{actor_id}@example.com"),
            employee_id: format!("E-{actor_id}"),
            display_name: "Test User".to_string(),
            role_persona: "Test persona".to_string(),
            department: "Test department".to_string(),
            home_location: "Sydney, NSW, Australia".to_string(),
            normal_countries_regions: vec!["Australia".to_string()],
            okta_user_id: format!("00u-{actor_id}"),
            databricks_username: format!("{actor_id}@example.com"),
            aws_principals: vec![AwsPrincipal {
                account_id: "123456789012".to_string(),
                principal_id: format!("AIDA{actor_id}"),
                arn: format!("arn:aws:iam::123456789012:user/{actor_id}"),
                role_name: None,
                role_session_name: None,
                access_key_id: Some(format!("AKIA{actor_id}")),
            }],
            service_account,
            tags: Vec::new(),
            rate_per_hour: None,
            active_start_hour: None,
            active_hours: None,
            timezone_offset: None,
            weekend_active: None,
            service_pattern: None,
        }
    }
}
