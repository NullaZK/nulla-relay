//! NULLA CLI library.

pub use polkadot_node_primitives::NODE_VERSION;

use clap::Parser;
use polkadot_service::IdentifyVariant;
use std::path::PathBuf;

#[allow(missing_docs)]
#[derive(Debug, Parser)]
pub enum Subcommand {
    /// Build a chain specification.
    #[deprecated(
        note = "build-spec command will be removed after 1/04/2026. Use export-chain-spec command instead"
    )]
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Export the chain specification.
    ExportChainSpec(sc_cli::ExportChainSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Remove the whole chain.
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Sub-commands concerned with benchmarking.
    /// The pallet benchmarking moved to the `pallet` sub-command.
    #[command(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),

    /// Key management CLI utilities
    #[command(subcommand)]
    Key(sc_cli::KeySubcommand),

    /// Db meta columns information.
    ChainInfo(sc_cli::ChainInfoCmd),
}

#[allow(missing_docs)]
#[derive(Debug, Parser)]
#[group(skip)]
pub struct RunCmd {
    #[clap(flatten)]
    pub base: sc_cli::RunCmd,

    /// Disable the BEEFY gadget.
    #[arg(long)]
    pub no_beefy: bool,

    /// Allows a validator to run insecurely outside of Secure Validator Mode.
    #[arg(long = "insecure-validator-i-know-what-i-do", requires = "validator")]
    pub insecure_validator: bool,

    /// Enable the block authoring backoff that is triggered when finality is lagging.
    #[arg(long)]
    pub force_authoring_backoff: bool,

    /// Add the destination address to the `pyroscope` agent.
    #[arg(long)]
    pub pyroscope_server: Option<String>,

    /// Disable automatic hardware benchmarks.
    #[arg(long)]
    pub no_hardware_benchmarks: bool,

    /// Overseer message capacity override.
    #[arg(long)]
    pub overseer_channel_capacity_override: Option<usize>,

    /// Path to the directory where auxiliary worker binaries reside.
    #[arg(long, value_name = "PATH")]
    pub workers_path: Option<PathBuf>,

    #[arg(long)]
    pub execute_workers_max_num: Option<usize>,
    #[arg(long)]
    pub prepare_workers_soft_max_num: Option<usize>,
    #[arg(long)]
    pub prepare_workers_hard_max_num: Option<usize>,
    #[arg(long, hide = true)]
    pub disable_worker_version_check: bool,

    #[arg(long)]
    pub keep_finalized_for: Option<u32>,

    #[arg(long, hide = true)]
    pub collator_protocol_hold_off: Option<u64>,
}

#[allow(missing_docs)]
#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[clap(flatten)]
    pub run: RunCmd,

    #[clap(flatten)]
    pub storage_monitor: sc_storage_monitor::StorageMonitorParams,
}

fn get_exec_name() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|pb| pb.file_name().map(|s| s.to_os_string()))
        .and_then(|s| s.into_string().ok())
}

impl sc_cli::SubstrateCli for Cli {
    fn impl_name() -> String {
        "NULLA Relay".into()
    }

    fn impl_version() -> String {
        let commit_hash = env!("SUBSTRATE_CLI_COMMIT_HASH");
        format!("{}-{commit_hash}", NODE_VERSION)
    }

    fn description() -> String {
        "NULLA Relay-chain Client Node".into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://example.com/nulla/issues".into()
    }

    fn copyright_start_year() -> i32 {
        2026
    }

    fn executable_name() -> String {
        "nulla-relay".into()
    }

    fn load_spec(&self, id: &str) -> std::result::Result<Box<dyn sc_service::ChainSpec>, String> {
        // Default to NULLA local testnet when no chain id is provided.
        let id = if id.is_empty() {
            "nulla-local"
        } else {
            id
        };

        Ok(match id {
            // Friendly aliases
            "local" => Box::new(polkadot_service::chain_spec::nulla_local_testnet_config()?),
            "nulla" => Box::new(polkadot_service::chain_spec::nulla_local_testnet_config()?),

            // Known embedded specs
            #[cfg(feature = "nulla-native")]
            "nulla-local" => Box::new(polkadot_service::chain_spec::nulla_local_testnet_config()?),

            // JSON file path
            path => {
                let path = std::path::PathBuf::from(path);
                let chain_spec = Box::new(polkadot_service::GenericChainSpec::from_json_file(path.clone())?)
                    as Box<dyn polkadot_service::ChainSpec>;

                chain_spec
            },
        })
    }
}
