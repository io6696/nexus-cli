//! Session setup and initialization

use crate::analytics::set_wallet_address_for_reporting;
use crate::config::Config;
use crate::environment::Environment;
use crate::events::Event;
use crate::orchestrator::OrchestratorClient;
use crate::runtime::start_authenticated_worker;
use ed25519_dalek::SigningKey;
use std::error::Error;
use sysinfo::System;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

/// Session data for both TUI and headless modes
#[derive(Debug)]
pub struct SessionData {
    /// Event receiver for worker events
    pub event_receiver: mpsc::Receiver<Event>,
    /// Join handles for worker tasks
    pub join_handles: Vec<JoinHandle<()>>,
    /// Shutdown sender to stop all workers
    pub shutdown_sender: broadcast::Sender<()>,
    /// Shutdown sender for max tasks completion
    pub max_tasks_shutdown_sender: broadcast::Sender<()>,
    /// Node ID
    pub node_id: u64,
    /// Orchestrator client
    pub orchestrator: OrchestratorClient,
    /// Number of workers (for display purposes)
    pub num_workers: usize,
}

/// Clamp the max-threads param by total logical cores and system memory.
pub fn clamp_threads(requested_threads: usize) -> usize {
    let mut sysinfo = System::new();
    sysinfo.refresh_memory();

    let total_system_memory: u64 = sysinfo.total_memory();
    
    let required_memory_per_thread: u64 = crate::consts::cli_consts::PROJECTED_MEMORY_REQUIREMENT;
    let max_threads_by_memory_u64 = total_system_memory / required_memory_per_thread;
    let memory_limit_usize = (max_threads_by_memory_u64.saturating_sub(1) as usize).max(1);
    
    let core_count = crate::system::num_cores();
    let absolute_max_threads = memory_limit_usize.min(core_count);
    return requested_threads.clamp(1, absolute_max_threads) as usize;
}

/// Sets up an authenticated worker session
///
/// This function handles all the common setup required for both TUI and headless modes:
/// 1. Creates signing key for the prover
/// 2. Sets up shutdown channel
/// 3. Starts authenticated worker
/// 4. Returns session data for mode-specific handling
///
/// # Arguments
/// * `config` - Resolved configuration with node_id and client_id
/// * `env` - Environment to connect to
/// * `max_threads` - Optional maximum number of threads for proving
/// * `max_difficulty` - Optional override for task difficulty
///
/// # Returns
/// * `Ok(SessionData)` - Successfully set up session
/// * `Err` - Session setup failed
pub async fn setup_session(
    config: Config,
    env: Environment,
    _check_mem: bool,
    max_threads: Option<u32>,
    max_tasks: Option<u32>,
    max_difficulty: Option<crate::nexus_orchestrator::TaskDifficulty>,
) -> Result<SessionData, Box<dyn Error>> {
    let node_id = config.node_id.parse::<u64>()?;
    let client_id = config.user_id;

    // Create a signing key for the prover
    let mut csprng = rand_core::OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    // Create orchestrator client
    let orchestrator_client = OrchestratorClient::new(env.clone());

    // Warn the user if the memory demands of their configuration is risky
    // if check_mem {
    //     warn_memory_configuration(max_threads);
    // }

    // Clamp the number of workers to [1,8]. Keep this low for now to avoid rate limiting.
    let num_workers: usize = clamp_threads(max_threads.unwrap_or(1) as usize);

    // Create shutdown channel - only one shutdown signal needed
    let (shutdown_sender, _) = broadcast::channel(1);

    // Set wallet for reporting
    set_wallet_address_for_reporting(config.wallet_address.clone());

    // Start authenticated worker (only mode we support now)
    let (event_receiver, join_handles, max_tasks_shutdown_sender) = start_authenticated_worker(
        node_id,
        signing_key,
        orchestrator_client.clone(),
        shutdown_sender.subscribe(),
        env,
        client_id,
        max_tasks,
        max_difficulty,
        num_workers,
    )
    .await;

    Ok(SessionData {
        event_receiver,
        join_handles,
        shutdown_sender,
        max_tasks_shutdown_sender,
        node_id,
        orchestrator: orchestrator_client,
        num_workers,
    })
}
