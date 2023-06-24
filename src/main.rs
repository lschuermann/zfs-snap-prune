use anyhow::{anyhow, bail, Context};
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use config::{Config, FileFormat, Value};
use regex::{Captures, Regex};
use std::borrow::Cow;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use std::collections::HashMap;

use libzetta::zfs::delegating::DelegatingZfsEngine;
use libzetta::zfs::description::DatasetKind;
use libzetta::zfs::{DestroyTiming, ZfsEngine};

enum Mode {
    PrepareFirst,
}

#[derive(Debug, Clone)]
struct SnapshotTimeExtractor {
    capture_group: usize,
    chrono_fmt: String,
}

impl SnapshotTimeExtractor {
    pub fn from_config(
        config: Value,
        snapshot_pattern_capture_groups: usize,
    ) -> anyhow::Result<Self> {
        let c = config
            .into_table()
            .map_err(|e| anyhow::Error::new(e).context("Cannot load snapshot_time config"))?;

        let source = c
            .get("source")
            .cloned()
            .ok_or_else(|| anyhow!("Snapshot time config has no source attribute"))
            .and_then(|source_val| source_val.into_string().map_err(|e| anyhow::Error::new(e)))?;

        if source != "capture_group" {
            bail!(format!("Unknown source attribute type \"{}\"", source));
        }

        let capture_group = c
            .get("capture_group")
            .cloned()
            .ok_or_else(|| anyhow!("Snapshot time config has no capture_group attribute"))
            .and_then(|source_val| source_val.into_int().map_err(|e| anyhow::Error::new(e)))?;

        if capture_group < 0
            || snapshot_pattern_capture_groups
                <= capture_group
                    .try_into()
                    .with_context(|| "Reinterpreting capture_group as usize")?
        {
            bail!(format!(
		"Snapshot time config capture_group out of range (pattern has at most {} capture groups)",
		snapshot_pattern_capture_groups,
	    ));
        }

        // Safe, as we've used try_into above:
        let capture_group = capture_group as usize;

        let format = c
            .get("format")
            .cloned()
            .ok_or_else(|| anyhow!("Snapshot time config has no format attribute"))
            .and_then(|format_val| format_val.into_string().map_err(|e| anyhow::Error::new(e)))?;

        if format != "chrono_fmt" {
            bail!(format!("Unknown format value \"{}\"", format));
        }

        let chrono_fmt = c
	    .get("chrono_fmt")
	    .cloned()
	    .ok_or_else(|| {
		anyhow!("Snapshot time config has no chrono_fmt attribute (required when using the \"chrono_fmt\" format)")
	    })
	    .and_then(|chrono_fmt_val| chrono_fmt_val.into_string().map_err(|e| {
		anyhow::Error::new(e)
	    }))?;

        Ok(SnapshotTimeExtractor {
            capture_group,
            chrono_fmt,
        })
    }

    pub fn extract(
        &self,
        captures: &Captures,
        snapshot_label: &str,
    ) -> anyhow::Result<DateTime<Utc>> {
        let m = captures.get(self.capture_group).ok_or_else(|| {
            anyhow!(
                "Can't extract capture group with index {} of snapshot label \"{}\"",
                self.capture_group,
                snapshot_label
            )
        })?;

        DateTime::parse_from_str(m.as_str(), &self.chrono_fmt)
            .with_context(|| {
                format!(
		"Parsing date-time from snapshot label capture-group \"{}\" with format string \"{}\"",
		m.as_str(), &self.chrono_fmt
	    )
            })
            .map(|dt| dt.into())
    }
}

#[derive(Debug, Clone)]
pub struct SimpleBucketsRetentionPolicy {
    buckets: Vec<(String, usize, usize)>,
}

impl SimpleBucketsRetentionPolicy {
    pub fn from_config(config: Value) -> anyhow::Result<Self> {
        let c = config
            .into_table()
            .map_err(|e| anyhow::Error::new(e).context("Cannot retention policy config"))?;

        let buckets = c
            .into_iter()
            .map(|(interval, count_val)| {
                let interval_sec = match interval.as_str() {
                    "latest" => 0,
                    "minutely" => 60,
                    "hourly" => 60 * 60,
                    "daily" => 60 * 60 * 24,
                    "weekly" => 60 * 60 * 24 * 7,
                    "monthly" => 60 * 60 * 24 * 30,
                    "yearly" => 60 * 60 * 24 * 365,
                    s => s
                        .parse::<usize>()
                        .with_context(|| format!("Interval \"{}\" unknown", s))?,
                };

                let count: usize = count_val
                    .into_int()
                    .with_context(|| {
                        format!(
                            "Parsing snapshot retention count for interval \"{}\"",
                            &interval
                        )
                    })?
                    .try_into()
                    .with_context(|| {
                        format!(
                            "Reinterpreting snapshot retention count for interval \"{}\" as usize",
                            &interval
                        )
                    })?;

                Ok((interval, interval_sec, count))
            })
            .collect::<anyhow::Result<Vec<(String, usize, usize)>>>()?;

        Ok(Self { buckets })
    }

    pub fn retain_in_place<S>(
        &self,
        _now: DateTime<Utc>,
        snapshots: &mut Vec<(S, DateTime<Utc>, bool)>,
    ) {
        // We iterate over the snapshots from latest to oldest. Thus sort them:
        snapshots.sort_unstable_by(|(_, a, _), (_, b, _)| b.partial_cmp(a).unwrap());

        // Allocate some local state to track how many snapshots we've decided
        // to retain already, and the timestamp of the last proccessed snapshot.
        let mut buckets_state: Vec<(usize, Option<DateTime<Utc>>)> =
            self.buckets.iter().map(|_| (0, None)).collect();

        // We're going to iterate over both simulatneously, and don't want to
        // leave any bucket out:
        assert!(buckets_state.len() == self.buckets.len());

        for (_snap_label, snap_time, retain) in snapshots.iter_mut() {
            // First, set retain = false. Either one of the inner loop
            // iterations can set it to true:
            *retain = false;

            for ((_bucket_label, interval_sec, bucket_max), (bucket_cur, bucket_last)) in
                self.buckets.iter().zip(buckets_state.iter_mut())
            {
                let bucket_delta_met = bucket_last
                    .map(|last| {
                        let diff_sec: i64 = last.signed_duration_since(*snap_time).num_seconds();
                        let diff_sec: usize = diff_sec
                            .try_into()
                            .expect("Retain snapshot time underflow / overflow!");
                        diff_sec >= *interval_sec
                    })
                    .unwrap_or(true);

                if *bucket_cur < *bucket_max && bucket_delta_met {
                    // Retain this snapshot and increment the state:
                    *retain = true;
                    *bucket_cur += 1;
                    *bucket_last = Some(*snap_time);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct JobConfig {
    _label: Option<String>,
    pool: String,
    dataset: String,
    recursive: bool,
    snapshot_regex: Regex,
    snapshot_time_extractor: SnapshotTimeExtractor,
    retention_policy: SimpleBucketsRetentionPolicy,
    description: String,
}

impl JobConfig {
    pub fn from_config(config: Value) -> anyhow::Result<Self> {
        let c = config
            .into_table()
            .map_err(|e| anyhow::Error::new(e).context("Cannot load job config"))?;

        let label = c
            .get("label")
            .cloned()
            .map(|label_val| label_val.into_string())
            .transpose()
            .map_err(|e| anyhow::Error::new(e).context("Failed to load job label"))?;

        // If we have a label for this job, use this as a context for
        // all subsequent error messages:
        let context = if let Some(ref l) = label {
            let ctx = format!("Loading job \"{}\"", l);
            log::debug!("{}", &ctx);
            ctx
        } else {
            format!("Loading unlabeled job")
        };

        let pool = c
            .get("pool")
            .cloned()
            .ok_or_else(|| anyhow!("Job has no pool attribute").context(context.clone()))
            .and_then(|pool_val| {
                pool_val
                    .into_string()
                    .map_err(|e| anyhow::Error::new(e).context(context.clone()))
            })?;

        let dataset = c
            .get("dataset")
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "Job has no dataset attribute (for the root dataset, use a single slash \"/\")"
                )
                .context(context.clone())
            })
            .and_then(|ds_val| {
                ds_val
                    .into_string()
                    .map_err(|e| anyhow::Error::new(e).context(context.clone()))
            })?;

        let context = if label.is_some() {
            context
        } else {
            format!(
                "Loading unlabeled job for pool \"{}\", dataset \"{}\"",
                pool, dataset,
            )
        };

        if !dataset.starts_with("/") {
            return Err(anyhow!("Dataset must start with a leading slash").context(context.clone()));
        }

        let recursive = c
            .get("recursive")
            .cloned()
            .map(|ds_val| {
                ds_val
                    .into_bool()
                    .map_err(|e| anyhow::Error::new(e).context(context.clone()))
            })
            .transpose()
            .map(|opt_recursive| opt_recursive.unwrap_or(false))?;

        let snapshot_pattern = c
            .get("snapshot_pattern")
            .cloned()
            .ok_or_else(|| {
                anyhow!("Job has no snapshot_pattern attribute").context(context.clone())
            })
            .and_then(|ds_val| {
                ds_val
                    .into_string()
                    .map_err(|e| anyhow::Error::new(e).context(context.clone()))
            })?;

        let snapshot_regex = Regex::new(&snapshot_pattern)
            .with_context(|| "Compiling snapshot_pattern regex")
            .with_context(|| context.clone())?;

        let snapshot_time_config = c.get("snapshot_time").cloned().ok_or_else(|| {
            anyhow!("Job has no snapshot_time configuration").context(context.clone())
        })?;

        let snapshot_time_extractor =
            SnapshotTimeExtractor::from_config(snapshot_time_config, snapshot_regex.captures_len())
                .with_context(|| "Constructing the SnapshotTimeExtractor")
                .with_context(|| context.clone())?;

        let retention_policy = c
            .get("retention_policy")
            .cloned()
            .ok_or_else(|| {
                anyhow!("Job has no retention_policy attribute").context(context.clone())
            })
            .and_then(|retention_policy_val| {
                retention_policy_val
                    .into_string()
                    .map_err(|e| anyhow::Error::new(e).context(context.clone()))
            })?;

        if retention_policy != "simple_buckets" {
            return Err(
                anyhow!(format!("Unknown retention policy \"{}\"", retention_policy))
                    .context(context.clone()),
            );
        }

        let retention_config = c.get("retention_config").cloned().ok_or_else(|| {
            anyhow!("Job has no retention_config configuration").context(context.clone())
        })?;

        let retention_policy = SimpleBucketsRetentionPolicy::from_config(retention_config)
            .with_context(|| "Constructing the SimpleBucketsRetentionPolicy")
            .with_context(|| context.clone())?;

        let description = if let Some(ref l) = label {
            format!("Job \"{}\"", l)
        } else {
            format!("Job for pool \"{}\", dataset \"{}\"", pool, dataset)
        };

        Ok(Self {
            _label: label,
            pool,
            dataset,
            recursive,
            snapshot_regex,
            snapshot_time_extractor,
            retention_policy,
            description,
        })
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn pool(&self) -> &str {
        &self.pool
    }

    pub fn prepare<'a>(
        self,
        _zfs: &impl ZfsEngine,
        pool_datasets: impl Iterator<Item = &'a (DatasetKind, PathBuf)>,
    ) -> anyhow::Result<Vec<PreparedJob>> {
        // Collect all datasets matching the confgured criteria,
        // evaluate the retention policy, etc. Because of recursion,
        // we may expand into multiple prepared jobs.

        // We first iterate over the pool_datasets, which contains all datasets
        // & snapshots of the pool returned by [`self.pool`]. We collect,
        // depending on whether this jobset has a recursive definition, all of
        // their (children) snapshots into a HashMap, with the key being the
        // dataset path:
        let mut datasets: HashMap<
            PathBuf,
            (DatasetKind, Vec<((PathBuf, String), DateTime<Utc>, bool)>),
        > = HashMap::new();

        for (kind, path) in pool_datasets {
            // In this iteration, we rely on the fact that filesystems or
            // volumes always precede their respective snapshots. This
            // assumption seems to be met in practice. TODO: fall back to an
            // implementation which performs sorting, should this not be the
            // case.
            match kind {
                DatasetKind::Filesystem | DatasetKind::Volume => {
                    // First, we need a path which has the pool name removed:
                    let no_pool_rel_path = path.strip_prefix(&self.pool).expect(
                        "Invariant violated: ZFS dataset path does not start with pool name!",
                    );
                    let no_pool_path = Path::new("/").join(no_pool_rel_path);

                    // This can then be used to test for a common prefix:
                    if no_pool_path == Path::new(&self.dataset)
                        || (self.recursive && no_pool_path.starts_with(&self.dataset))
                    {
                        // We never store our custom, modified paths as the
                        // index into the HashMap, or as the snapshot path, as
                        // these are fed back into the libzetta crate:
                        assert!(datasets
                            .insert(path.clone(), (kind.clone(), vec![]))
                            .is_none());
                    }
                }
                DatasetKind::Snapshot => {
                    // In this case, the path contains a single `@` character in
                    // the end. We create the original, non-snapshot path by
                    // converting to unicode, and splitting off the `@` in the
                    // end. We can't really deal with paths having an unknown
                    // charset, so return an error if something's off:
                    let path_str = path.to_str().ok_or(anyhow!(format!(
                        "ZFS dataset path is not unicode: {:?}",
                        path
                    )))?;
                    let mut path_str_iter = path_str.split('@');

                    // First split substring must exist as per logic in `str::split`:
                    let dataset = path_str_iter.next().unwrap();

                    // Next split substring must exist for ZFS snapshots:
                    let snapshot_label = path_str_iter.next().ok_or(anyhow!(format!(
                        "Cannot extract ZFS snapshot label from path: {:?}",
                        path_str
                    )))?;

                    // Next split iteration must return `None`:
                    if path_str_iter.next().is_some() {
                        bail!("ZFS snapshot has multiple '@' characters!");
                    }

                    // From this dataset, we can create a path which is not
                    // prefixed by the pool:
                    let no_pool_rel_dataset = dataset.strip_prefix(&self.pool).expect(
                        "Invariant violated: ZFS dataset path does not start with pool name!",
                    );
                    let no_pool_dataset = Path::new("/").join(no_pool_rel_dataset);

                    // Now that the returned path has been decomposed, check
                    // whether this snapshot refers to a dataset that we expect
                    // to have iterated over previously:
                    if !(no_pool_dataset == Path::new(&self.dataset)
                        || (self.recursive && no_pool_dataset.starts_with(&self.dataset)))
                    {
                        // Ignore this dataset
                        continue;
                    }

                    // Check whether this snapshot matches the supplied pattern,
                    // and extract the DateTime:
                    let captures =
                        if let Some(captures) = self.snapshot_regex.captures(snapshot_label) {
                            captures
                        } else {
                            // The snapshot name does not meet our pattern, skip it!
                            continue;
                        };

                    let snapshot_time = self
                        .snapshot_time_extractor
                        .extract(&captures, snapshot_label)
                        .with_context(|| {
                            format!("Extracting the time from matching snapshot: {:?}", path)
                        })?;

                    // Now, find the corresponding dataset and add the snapshot:
                    let dataset_entry = datasets.get_mut(Path::new(dataset)).expect(
                        "Invariant violated: ZFS snapshot was not preceded by its dataset!",
                    );

                    // Store the unmodified, full snapshot path, in addition to
                    // the extracted DateTime and a dummy boolean flag, such
                    // that we can then run the retention policy in-place:
                    dataset_entry.1.push((
                        (path.clone(), snapshot_label.to_string()),
                        snapshot_time,
                        true,
                    ));
                }
            }
        }

        let now = chrono::offset::Utc::now();

        // Now, for each entry in the hashmap, create its own prepared job:
        Ok(datasets
            .into_iter()
            .map(|(dataset, (kind, mut snapshots))| {
                // Evaluate which snapshots to retain:
                self.retention_policy.retain_in_place(now, &mut snapshots);

                PreparedJob {
                    config: self.clone(),
                    dataset_path: dataset,
                    dataset_kind: kind,
                    snapshots,
                }
            })
            .collect())
    }
}

struct PreparedJob {
    config: JobConfig,
    dataset_path: PathBuf,
    dataset_kind: DatasetKind,
    snapshots: Vec<((PathBuf, String), DateTime<Utc>, bool)>,
}

impl PreparedJob {
    pub fn describe<'a>(&'a self) -> Cow<'a, str> {
        let mut desc = format!(
            "Prepared job for dataset {:?} ({:?}, generated from {}). Snapshots:\n",
            self.dataset_path,
            self.dataset_kind,
            self.config.description()
        );

        for ((_, snap_label), _, retain) in self.snapshots.iter() {
            write!(
                desc,
                "    \"{}\": {}\n",
                snap_label,
                if *retain { "retain" } else { "destroy" }
            )
            .unwrap();
        }

        Cow::Owned(desc)
    }

    pub fn execute(self, zfs: &impl ZfsEngine) -> anyhow::Result<()> {
        let to_destroy: Vec<PathBuf> = self
            .snapshots
            .into_iter()
            .filter(|(_, _, retain)| !retain)
            // .map(|((snapshot_path, _), _, _)| snapshot_path.clone())
            .map(|((snapshot_path, _), _, _)| snapshot_path)
            .collect();

        log::info!(
            "Executing job for dataset {:?}, destroying {} snapshots",
            self.dataset_path,
            to_destroy.len()
        );
        zfs.destroy_snapshots(&to_destroy, DestroyTiming::RightNow)?;

        Ok(())
    }
}

#[derive(ValueEnum, Debug, Clone)]
enum LoggerArg {
    Stderr,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: String,

    #[arg(short = 'n', long)]
    dry_run: bool,

    #[arg(long, default_value = "stderr")]
    logger: LoggerArg,
}

fn main() {
    let args = Args::parse();

    // First, initialize the logging facility:
    match &args.logger {
        LoggerArg::Stderr => {
            simple_logger::init_with_level(log::Level::Trace).unwrap();
        }
    };

    // Load the app configuration:
    let config = match Config::builder()
        .add_source(config::File::new(&args.config, FileFormat::Yaml))
        .build()
    {
        Ok(config) => config,
        Err(e) => {
            log::error!("Failed to load config: {:?}", e);
            std::process::exit(1);
        }
    };

    let mode = match config
        .get_string("mode")
        .map_err(|e| anyhow::Error::new(e).context("Missing \"mode\" configuraiton"))
        .and_then(|mode_config| match mode_config.as_str() {
            "prepare_first" => Ok(Mode::PrepareFirst),
            _ => Err(anyhow!("Unknown \"mode\" configuration: {}", mode_config)),
        }) {
        Ok(mode) => mode,
        Err(e) => {
            log::error!("Failed to load operating mode config: {:?}", e);
            std::process::exit(1);
        }
    };

    // Load all jobs first. This means that we fully parse them and
    // validate that their config looks correct. However, we don't
    // begin to evaluate them just yet.
    let jobs: Vec<JobConfig> = match config
        .get_array("jobs")
        .map_err(|e| anyhow::Error::new(e).context("Failed to load \"jobs\" array from config"))
        .and_then(|job_config_arr| {
            job_config_arr
                .into_iter()
                .map(|job_config_val| JobConfig::from_config(job_config_val))
                .collect()
        }) {
        Ok(jobs) => jobs,
        Err(e) => {
            log::error!("Failed to load jobs: {:?}", e);
            std::process::exit(1);
        }
    };

    // Once all jobs are loaded, we use different strategies as
    // defined in the configuration. Initialize the ZFS engine, which
    // is required in all modes:
    let zfs = match DelegatingZfsEngine::new() {
        Ok(zfs) => zfs,
        Err(e) => {
            log::error!("Error creating ZFS engine: {:?}", e);
            std::process::exit(1);
        }
    };

    match mode {
        Mode::PrepareFirst => {
            // We perform an optimization: listing ZFS datasets can
            // take a really long time, and libzetta does not allow us
            // to retrieve only a subset of datasets (only allows
            // filtering by type). Hence, when we prepare a job for a
            // pool, cache the datasets in a HashMap to be able to
            // reuse it later:
            let mut cached_datasets = HashMap::new();

            let prepared_jobs: Vec<Vec<PreparedJob>> = match jobs
                .into_iter()
                .map(|jc| {
                    let datasets = cached_datasets
                        .entry(jc.pool().to_string())
                        .or_insert_with_key(|pool| {
                            // TODO: fix error handling!
                            zfs.list(pool).unwrap()
                        });

                    let description = jc.description().to_string();

                    jc.prepare(&zfs, datasets.iter()).map(|prepared| {
                        log::info!(
                            "{} generated {} prepared jobs.",
                            description,
                            prepared.len()
                        );
                        for p in prepared.iter() {
                            println!("{}", p.describe());
                        }
                        prepared
                    })
                })
                .collect()
            {
                Ok(prepared_jobs) => prepared_jobs,
                Err(e) => {
                    log::error!("Error while preparing jobs: {:?}", e);
                    std::process::exit(1);
                }
            };

            // Only prepare for dry run, execute for non dry-run:
            if !args.dry_run {
                for job in prepared_jobs.into_iter().flat_map(|v| v.into_iter()) {
                    // let desc = job.describe().to_string();
                    if let Err(e) = job.execute(&zfs) {
                        log::error!("Error while executing job: {:?}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    };
}
