//! Proving pipeline that orchestrates the full proving process

use futures::future::join_all;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken; // Import for join_all

use super::engine::ProvingEngine;
use super::input::InputParser;
use super::types::ProverError;
use crate::analytics::track_verification_failed;
use crate::environment::Environment;
use crate::task::Task;
use nexus_sdk::stwo::seq::Proof;
use sha3::{Digest, Keccak256};

/// Orchestrates the complete proving pipeline
pub struct ProvingPipeline;

impl ProvingPipeline {
    /// Execute authenticated proving for a task
    pub async fn prove_authenticated(
        task: &Task,
        environment: &Environment,
        client_id: &str,
        num_workers: usize,
    ) -> Result<(Vec<Proof>, String, Vec<String>), ProverError> {
        match task.program_id.as_str() {
            "fib_input_initial" => {
                Self::prove_fib_task(task, environment, client_id, num_workers).await
            }
            _ => Err(ProverError::MalformedTask(format!(
                "Unsupported program ID: {}",
                task.program_id
            ))),
        }
    }

    /// Process fibonacci proving task with multiple inputs
    async fn prove_fib_task(
        task: &Task,
        environment: &Environment,
        client_id: &str,
        num_workers: usize,
    ) -> Result<(Vec<Proof>, String, Vec<String>), ProverError> {
        let all_inputs = task.all_inputs();

        if all_inputs.is_empty() {
            return Err(ProverError::MalformedTask(
                "No inputs provided for task".to_string(),
            ));
        }

        // Shared references for concurrent access
        let task_shared = Arc::new(task.clone());
        let environment_shared = Arc::new(environment.clone());
        let client_id_shared = Arc::new(client_id.to_string());

        let semaphore = Arc::new(Semaphore::new(num_workers));
        let cancellation_token = CancellationToken::new();

        let handles: Vec<_> = all_inputs
            .iter()
            .enumerate()
            .map(|(input_index, input_data)| {
                let task_ref = Arc::clone(&task_shared);
                let environment_ref = Arc::clone(&environment_shared);
                let client_id_ref = Arc::clone(&client_id_shared);
                let input_data = input_data.clone();
                let semaphore_ref = Arc::clone(&semaphore);
                let cancellation_ref = cancellation_token.clone();

                tokio::spawn(async move {
                    // Return type is Result<(Proof, String, usize), ProverError>

                    if cancellation_ref.is_cancelled() {
                        return Err(ProverError::Cancelled);
                    }

                    // Acquire permit: limits active workers to num_workers
                    let _permit = semaphore_ref.acquire_owned().await.map_err(|_| {
                        ProverError::Internal("Worker semaphore closed".to_string())
                    })?;

                    if cancellation_ref.is_cancelled() {
                        return Err(ProverError::Cancelled);
                    }

                    // Step 1: Parse and validate input (embed index in error)
                    let inputs = InputParser::parse_triple_input(&input_data).map_err(|e| {
                        ProverError::MalformedTask(format!(
                            "Input {}: Parsing failed: {}",
                            input_index, e
                        ))
                    })?;

                    // Step 2: Generate and verify proof (embed index in error)
                    let proof = ProvingEngine::prove_and_validate(
                        &inputs,
                        &task_ref,
                        &environment_ref,
                        &client_id_ref,
                    )
                    .await
                    .map_err(|e| {
                        ProverError::Stwo(format!(
                            "Input {}: Proof validation failed: {}",
                            input_index, e
                        ))
                    })?;

                    // Step 3: Generate proof hash
                    let proof_hash = Self::generate_proof_hash(&proof);

                    Ok((proof, proof_hash, input_index))
                })
            })
            .collect();

        // Await all spawned tasks concurrently
        let results = join_all(handles).await;

        let mut all_proofs = Vec::new();
        let mut proof_hashes = Vec::new();
        let mut verification_failures = Vec::new();

        for result in results {
            match result {
                Ok(inner_result) => match inner_result {
                    // Task succeeded
                    Ok((proof, proof_hash, _input_index)) => {
                        all_proofs.push(proof);
                        proof_hashes.push(proof_hash);
                    }
                    // Task failed with a ProverError
                    Err(e) => {
                        match e {
                            ProverError::Stwo(indexed_e) => {
                                let separator = ": ";
                                if let Some((index_part, error_msg)) =
                                    indexed_e.split_once(separator)
                                {
                                    let input_index = index_part
                                        .trim_start_matches("Input ")
                                        .parse::<usize>()
                                        .unwrap_or(0);

                                    verification_failures.push((
                                        task_shared.clone(),
                                        format!("Input {}: {}", input_index, error_msg),
                                        environment_shared.clone(),
                                        client_id_shared.clone(),
                                    ));
                                } else {
                                    cancellation_token.cancel();
                                    return Err(ProverError::Stwo(indexed_e));
                                }
                            }
                            ProverError::GuestProgram(indexed_e) => {
                                let separator = ": ";
                                if let Some((index_part, error_msg)) =
                                    indexed_e.split_once(separator)
                                {
                                    let input_index = index_part
                                        .trim_start_matches("Input ")
                                        .parse::<usize>()
                                        .unwrap_or(0);

                                    verification_failures.push((
                                        task_shared.clone(),
                                        format!("Input {}: {}", input_index, error_msg),
                                        environment_shared.clone(),
                                        client_id_shared.clone(),
                                    ));
                                } else {
                                    cancellation_token.cancel();
                                    return Err(ProverError::GuestProgram(indexed_e));
                                }
                            }
                            ProverError::Cancelled => {
                                continue;
                            }
                            _ => {
                                // Critical, non-recoverable error
                                cancellation_token.cancel();
                                return Err(e);
                            }
                        }
                    }
                },
                // Task panicked or failed to join
                Err(join_error) => {
                    cancellation_token.cancel();
                    return Err(ProverError::JoinError(join_error));
                }
            }
        }

        // Handle all verification failures in batch
        let failure_count = verification_failures.len();
        for (task, error_msg, env, client) in verification_failures {
            tokio::spawn(track_verification_failed(
                (*task).clone(),
                error_msg,
                (*env).clone(),
                (*client).clone(),
            ));
        }

        // Return final error if any verification failed
        if failure_count > 0 {
            return Err(ProverError::MalformedTask(format!(
                "{} inputs failed verification",
                failure_count
            )));
        }

        let final_proof_hash = Self::combine_proof_hashes(task, &proof_hashes);

        Ok((all_proofs, final_proof_hash, proof_hashes))
    }

    /// Generate hash for a proof
    fn generate_proof_hash(proof: &Proof) -> String {
        let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
        format!("{:x}", Keccak256::digest(&proof_bytes))
    }

    /// Combine multiple proof hashes based on task type
    fn combine_proof_hashes(task: &Task, proof_hashes: &[String]) -> String {
        match task.task_type {
            crate::nexus_orchestrator::TaskType::AllProofHashes
            | crate::nexus_orchestrator::TaskType::ProofHash => {
                Task::combine_proof_hashes(proof_hashes)
            }
            _ => proof_hashes.first().cloned().unwrap_or_default(),
        }
    }
}
