// NULLA command dispatch and node runner.
use crate::cli::{Cli, Subcommand, NODE_VERSION};
use frame_benchmarking_cli::{BenchmarkCmd, SUBSTRATE_REFERENCE_HARDWARE};
use futures::future::TryFutureExt;
use polkadot_service::{self, HeaderBackend, IdentifyVariant};
#[cfg(feature = "pyroscope")]
use pyroscope_pprofrs::{pprof_backend, PprofConfig};
use sc_cli::SubstrateCli;
use sp_core::crypto::Ss58AddressFormatRegistry;

pub use crate::error::Error;
#[cfg(feature = "pyroscope")]
use std::net::ToSocketAddrs;

type Result<T> = std::result::Result<T, Error>;

fn set_default_ss58_version(_spec: &Box<dyn polkadot_service::ChainSpec>) {
    let ss58_version = Ss58AddressFormatRegistry::SubstrateAccount.into();
    sp_core::crypto::set_default_ss58_version(ss58_version);
}

#[cfg(feature = "malus")]
pub fn run_node(
    run: Cli,
    overseer_gen: impl polkadot_service::OverseerGen,
    malus_finality_delay: Option<u32>,
) -> Result<()> {
    run_node_inner(run, overseer_gen, malus_finality_delay, |_logger_builder, _config| {})
}

fn run_node_inner<F>(
    cli: Cli,
    overseer_gen: impl polkadot_service::OverseerGen,
    maybe_malus_finality_delay: Option<u32>,
    logger_hook: F,
) -> Result<()>
where
    F: FnOnce(&mut sc_cli::LoggerBuilder, &sc_service::Configuration),
{
    let runner = cli
        .create_runner_with_logger_hook::<_, _, F>(&cli.run.base, logger_hook)
        .map_err(Error::from)?;
    let chain_spec = &runner.config().chain_spec;

    // By default, enable BEEFY on all networks, unless explicitly disabled through CLI.
    let enable_beefy = !cli.run.no_beefy;

    set_default_ss58_version(chain_spec);

    let node_version =
        if cli.run.disable_worker_version_check { None } else { Some(NODE_VERSION.to_string()) };

    let secure_validator_mode = cli.run.base.validator && !cli.run.insecure_validator;

    let collator_protocol_hold_off = cli
        .run
        .collator_protocol_hold_off
        .map(std::time::Duration::from_millis);

    runner.run_node_until_exit(move |config| async move {
        let hwbench = (!cli.run.no_hardware_benchmarks)
            .then(|| {
                config.database.path().map(|database_path| {
                    let _ = std::fs::create_dir_all(&database_path);
                    sc_sysinfo::gather_hwbench(Some(database_path), &SUBSTRATE_REFERENCE_HARDWARE)
                })
            })
            .flatten();

        let database_source = config.database.clone();
        let task_manager = polkadot_service::build_full(
            config,
            polkadot_service::NewFullParams {
                is_parachain_node: polkadot_service::IsParachainNode::No,
                enable_beefy,
                force_authoring_backoff: cli.run.force_authoring_backoff,
                telemetry_worker_handle: None,
                node_version,
                secure_validator_mode,
                workers_path: cli.run.workers_path,
                workers_names: None,
                overseer_gen,
                overseer_message_channel_capacity_override: cli
                    .run
                    .overseer_channel_capacity_override,
                malus_finality_delay: maybe_malus_finality_delay,
                hwbench,
                execute_workers_max_num: cli.run.execute_workers_max_num,
                prepare_workers_hard_max_num: cli.run.prepare_workers_hard_max_num,
                prepare_workers_soft_max_num: cli.run.prepare_workers_soft_max_num,
                keep_finalized_for: cli.run.keep_finalized_for,
                invulnerable_ah_collators: Default::default(),
                collator_protocol_hold_off,
            },
        )
        .map(|full| full.task_manager)?;

        if let Some(path) = database_source.path() {
            sc_storage_monitor::StorageMonitorService::try_spawn(
                cli.storage_monitor,
                path.to_path_buf(),
                &task_manager.spawn_essential_handle(),
            )?;
        }

        Ok(task_manager)
    })
}

/// Parses NULLA-specific CLI arguments and run the service.
pub fn run() -> Result<()> {
    let cli: Cli = Cli::from_args();

    #[cfg(feature = "pyroscope")]
    let mut pyroscope_agent_maybe = if let Some(ref agent_addr) = cli.run.pyroscope_server {
        let address = agent_addr
            .to_socket_addrs()
            .map_err(Error::AddressResolutionFailure)?
            .next()
            .ok_or_else(|| Error::AddressResolutionMissing)?;
        let agent = pyroscope::PyroscopeAgent::builder(
            "http://".to_owned() + address.to_string().as_str(),
            "nulla-relay".to_owned(),
        )
        .backend(pprof_backend(PprofConfig::new().sample_rate(113)))
        .build()?;
        Some(agent.start()?)
    } else {
        None
    };

    #[cfg(not(feature = "pyroscope"))]
    if cli.run.pyroscope_server.is_some() {
        return Err(Error::PyroscopeNotCompiledIn)
    }

    match &cli.subcommand {
        None => run_node_inner(
            cli,
            polkadot_service::ValidatorOverseerGen,
            None,
            polkadot_node_metrics::logger_hook(),
        ),
        #[allow(deprecated)]
        Some(Subcommand::BuildSpec(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            Ok(runner.sync_run(|config| cmd.run(config.chain_spec, config.network))?)
        },
        Some(Subcommand::ExportChainSpec(cmd)) => {
            let spec = cli.load_spec(&cmd.chain)?;
            cmd.run(spec).map_err(Into::into)
        },
        Some(Subcommand::CheckBlock(cmd)) => {
            let runner = cli.create_runner(cmd).map_err(Error::SubstrateCli)?;
            let chain_spec = &runner.config().chain_spec;
            set_default_ss58_version(chain_spec);
            runner.async_run(|mut config| {
                let (client, _, import_queue, task_manager) =
                    polkadot_service::new_chain_ops(&mut config)?;
                Ok((cmd.run(client, import_queue).map_err(Error::SubstrateCli), task_manager))
            })
        },
        Some(Subcommand::ExportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            let chain_spec = &runner.config().chain_spec;
            set_default_ss58_version(chain_spec);
            Ok(runner.async_run(|mut config| {
                let (client, _, _, task_manager) =
                    polkadot_service::new_chain_ops(&mut config).map_err(Error::PolkadotService)?;
                Ok((cmd.run(client, config.database).map_err(Error::SubstrateCli), task_manager))
            })?)
        },
        Some(Subcommand::ExportState(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            let chain_spec = &runner.config().chain_spec;
            set_default_ss58_version(chain_spec);
            Ok(runner.async_run(|mut config| {
                let (client, _, _, task_manager) = polkadot_service::new_chain_ops(&mut config)?;
                Ok((cmd.run(client, config.chain_spec).map_err(Error::SubstrateCli), task_manager))
            })?)
        },
        Some(Subcommand::ImportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            let chain_spec = &runner.config().chain_spec;
            set_default_ss58_version(chain_spec);
            Ok(runner.async_run(|mut config| {
                let (client, _, import_queue, task_manager) =
                    polkadot_service::new_chain_ops(&mut config)?;
                Ok((cmd.run(client, import_queue).map_err(Error::SubstrateCli), task_manager))
            })?)
        },
        Some(Subcommand::PurgeChain(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            Ok(runner.sync_run(|config| cmd.run(config.database))?)
        },
        Some(Subcommand::Revert(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            let chain_spec = &runner.config().chain_spec;
            set_default_ss58_version(chain_spec);
            Ok(runner.async_run(|mut config| {
                let (client, backend, _, task_manager) =
                    polkadot_service::new_chain_ops(&mut config)?;
                let task_handle = task_manager.spawn_handle();
                let aux_revert = Box::new(|client, backend, blocks| {
                    polkadot_service::revert_backend(client, backend, blocks, config, task_handle)
                        .map_err(|err| match err {
                            polkadot_service::Error::Blockchain(err) => err.into(),
                            err => sc_cli::Error::Application(err.into()),
                        })
                });
                Ok((
                    cmd.run(client, backend, Some(aux_revert)).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?)
        },
        Some(Subcommand::Benchmark(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            match cmd {
                #[cfg(not(feature = "runtime-benchmarks"))]
                BenchmarkCmd::Storage(_) =>
                    return Err(sc_cli::Error::Input(
                        "Compile with --features=runtime-benchmarks \
                        to enable storage benchmarks.".into(),
                    )
                    .into()),
                #[cfg(feature = "runtime-benchmarks")]
                BenchmarkCmd::Storage(cmd) => runner.sync_run(|mut config| {
                    let (client, backend, _, _) = polkadot_service::new_chain_ops(&mut config)?;
                    let db = backend.expose_db();
                    let storage = backend.expose_storage();
                    let shared_trie_cache = backend.expose_shared_trie_cache();
                    cmd.run(config, client.clone(), db, storage, shared_trie_cache)
                        .map_err(Error::SubstrateCli)
                }),
                BenchmarkCmd::Block(cmd) => runner.sync_run(|mut config| {
                    let (client, _, _, _) = polkadot_service::new_chain_ops(&mut config)?;
                    cmd.run(client.clone()).map_err(Error::SubstrateCli)
                }),
                BenchmarkCmd::Overhead(cmd) => runner.sync_run(|config| {
                    if cmd.params.runtime.is_some() {
                        return Err(sc_cli::Error::Input(
                            "NULLA binary does not support `--runtime` flag for `benchmark overhead`. Please provide a chain spec or use the `frame-omni-bencher`."
                                .into(),
                        )
                        .into())
                    }
                    cmd.run_with_default_builder_and_spec::<polkadot_service::Block, ()>(
                        Some(config.chain_spec),
                    )
                    .map_err(Error::SubstrateCli)
                }),
                BenchmarkCmd::Extrinsic(cmd) => runner.sync_run(|mut config| {
                    let (client, _, _, _) = polkadot_service::new_chain_ops(&mut config)?;
                    let header = client.header(client.info().genesis_hash).unwrap().unwrap();
                    let inherent_data = polkadot_service::benchmarking::benchmark_inherent_data(header)
                        .map_err(|e| format!("generating inherent data: {:?}", e))?;
                    let remark_builder = frame_benchmarking_cli::SubstrateRemarkBuilder::new_from_client(client.clone())?;
                    let tka_builder = polkadot_service::benchmarking::TransferKeepAliveBuilder::new(
                        client.clone(),
                        sp_keyring::Sr25519Keyring::Alice.to_account_id(),
                        config.chain_spec.identify_chain(),
                    );
                    let ext_factory = frame_benchmarking_cli::ExtrinsicFactory(vec![
                        Box::new(remark_builder),
                        Box::new(tka_builder),
                    ]);
                    cmd.run(client.clone(), inherent_data, Vec::new(), &ext_factory)
                        .map_err(Error::SubstrateCli)
                }),
                BenchmarkCmd::Pallet(cmd) => {
                    let runner_chain = &runner.config().chain_spec;
                    set_default_ss58_version(runner_chain);
                    if cfg!(feature = "runtime-benchmarks") {
                        runner.sync_run(|config| {
                            cmd.run_with_spec::<sp_runtime::traits::HashingFor<polkadot_service::Block>, ()>(
                                Some(config.chain_spec),
                            )
                            .map_err(|e| Error::SubstrateCli(e))
                        })
                    } else {
                        Err(sc_cli::Error::Input(
                            "Benchmarking wasn't enabled when building the node. \
                You can enable it with `--features runtime-benchmarks`."
                                .into(),
                        )
                        .into())
                    }
                },
                BenchmarkCmd::Machine(cmd) => runner.sync_run(|config| {
                    cmd.run(&config, SUBSTRATE_REFERENCE_HARDWARE.clone())
                        .map_err(Error::SubstrateCli)
                }),
                #[allow(unreachable_patterns)]
                _ => Err(Error::CommandNotImplemented),
            }
        },
        Some(Subcommand::Key(cmd)) => Ok(cmd.run(&cli)?),
        Some(Subcommand::ChainInfo(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            Ok(runner.sync_run(|config| cmd.run::<polkadot_service::Block>(&config))?)
        },
    }?;

    #[cfg(feature = "pyroscope")]
    if let Some(pyroscope_agent) = pyroscope_agent_maybe.take() {
        let agent = pyroscope_agent.stop()?;
        agent.shutdown();
    }
    Ok(())
}
