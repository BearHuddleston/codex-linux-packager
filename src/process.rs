//! Shell-free subprocess execution with deterministic environments and bounds.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process_group};
use thiserror::Error;

/// Complete, shell-free subprocess specification.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    /// Absolute executable path.
    pub program: PathBuf,
    /// Exact argument vector, excluding argv[0].
    pub arguments: Vec<OsString>,
    /// Exact working directory.
    pub working_directory: PathBuf,
    /// Complete environment after `env_clear`.
    pub environment: BTreeMap<OsString, OsString>,
    /// Wall-clock deadline.
    pub timeout: Duration,
    /// Maximum retained bytes for each of stdout and stderr.
    pub maximum_output_bytes: usize,
}

/// Bounded process result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    /// Raw platform exit status.
    pub status: ExitStatus,
    /// Retained stdout bytes.
    pub stdout: Vec<u8>,
    /// Retained stderr bytes.
    pub stderr: Vec<u8>,
}

/// Bounded output plus whether the process was deliberately terminated at its
/// deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    /// Captured process status and streams.
    pub output: ProcessOutput,
    /// True only when the configured wall-clock deadline terminated the group.
    pub timed_out: bool,
}

/// Subprocess construction, timeout, capture, or cleanup failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProcessError {
    /// Specification violates the shell-free deterministic contract.
    #[error("invalid process specification: {0}")]
    Specification(String),
    /// Process could not be spawned or waited for.
    #[error("subprocess operating-system error: {0}")]
    OperatingSystem(String),
    /// Process exceeded its wall-clock deadline and was terminated.
    #[error("subprocess exceeded timeout of {0:?}")]
    Timeout(Duration),
    /// Process emitted more than the retained-output bound.
    #[error("subprocess output exceeded {0} bytes")]
    OutputLimit(usize),
    /// A capture thread failed.
    #[error("subprocess output capture failed: {0}")]
    Capture(String),
}

#[derive(Debug)]
struct Capture {
    bytes: Vec<u8>,
    overflowed: bool,
}

/// Runs one process without a shell in a new process group. Stdout and stderr
/// are drained concurrently, retained only up to the configured bound, and the
/// whole group is terminated on timeout or output overflow.
pub fn run_bounded(specification: &ProcessSpec) -> Result<ProcessOutput, ProcessError> {
    let outcome = run_bounded_observing_timeout(specification)?;
    if outcome.timed_out {
        return Err(ProcessError::Timeout(specification.timeout));
    }
    Ok(outcome.output)
}

/// Runs a bounded process while returning captured output for an expected
/// timeout. Output overflow and all operating-system failures remain errors.
pub fn run_bounded_observing_timeout(
    specification: &ProcessSpec,
) -> Result<ProcessOutcome, ProcessError> {
    validate_specification(specification)?;
    let mut command = Command::new(&specification.program);
    command
        .args(&specification.arguments)
        .current_dir(&specification.working_directory)
        .env_clear()
        .envs(&specification.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| ProcessError::OperatingSystem(error.to_string()))?;
    let pid = Pid::from_child(&child);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProcessError::OperatingSystem("stdout pipe is absent".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ProcessError::OperatingSystem("stderr pipe is absent".to_owned()))?;
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_capture = spawn_capture(
        stdout,
        specification.maximum_output_bytes,
        Arc::clone(&overflow),
    );
    let stderr_capture = spawn_capture(
        stderr,
        specification.maximum_output_bytes,
        Arc::clone(&overflow),
    );

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if overflow.load(Ordering::Acquire) {
            terminate_group(&mut child, pid)?;
            break child
                .try_wait()
                .map_err(|error| ProcessError::OperatingSystem(error.to_string()))?
                .ok_or_else(|| {
                    ProcessError::OperatingSystem(
                        "subprocess remained live after group termination".to_owned(),
                    )
                })?;
        }
        if started.elapsed() >= specification.timeout {
            timed_out = true;
            terminate_group(&mut child, pid)?;
            break child
                .try_wait()
                .map_err(|error| ProcessError::OperatingSystem(error.to_string()))?
                .ok_or_else(|| {
                    ProcessError::OperatingSystem(
                        "subprocess remained live after timeout termination".to_owned(),
                    )
                })?;
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| ProcessError::OperatingSystem(error.to_string()))?
        {
            let _ = kill_process_group(pid, Signal::TERM);
            let _ = kill_process_group(pid, Signal::KILL);
            break status;
        }
        thread::sleep(Duration::from_millis(10));
    };

    let stdout = join_capture(stdout_capture)?;
    let stderr = join_capture(stderr_capture)?;
    if stdout.overflowed || stderr.overflowed {
        return Err(ProcessError::OutputLimit(
            specification.maximum_output_bytes,
        ));
    }
    Ok(ProcessOutcome {
        output: ProcessOutput {
            status,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        },
        timed_out,
    })
}

fn validate_specification(specification: &ProcessSpec) -> Result<(), ProcessError> {
    if !specification.program.is_absolute() {
        return Err(ProcessError::Specification(
            "program path must be absolute".to_owned(),
        ));
    }
    if !specification.working_directory.is_absolute() {
        return Err(ProcessError::Specification(
            "working directory must be absolute".to_owned(),
        ));
    }
    if specification.timeout.is_zero() || specification.timeout > Duration::from_secs(60 * 60) {
        return Err(ProcessError::Specification(
            "timeout must be within 1 nanosecond..=1 hour".to_owned(),
        ));
    }
    if specification.maximum_output_bytes == 0
        || specification.maximum_output_bytes > 16 * 1024 * 1024
    {
        return Err(ProcessError::Specification(
            "output bound must be within 1..=16 MiB per stream".to_owned(),
        ));
    }
    Ok(())
}

fn spawn_capture(
    mut reader: impl Read + Send + 'static,
    maximum: usize,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Capture, std::io::Error>> {
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(maximum.min(64 * 1024));
        let mut buffer = [0_u8; 8192];
        let mut overflowed = false;
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            let remaining = maximum.saturating_sub(retained.len());
            let keep = remaining.min(count);
            retained.extend_from_slice(&buffer[..keep]);
            if keep != count {
                overflowed = true;
                overflow.store(true, Ordering::Release);
            }
        }
        Ok(Capture {
            bytes: retained,
            overflowed,
        })
    })
}

fn join_capture(
    handle: thread::JoinHandle<Result<Capture, std::io::Error>>,
) -> Result<Capture, ProcessError> {
    handle
        .join()
        .map_err(|_| ProcessError::Capture("capture thread panicked".to_owned()))?
        .map_err(|error| ProcessError::Capture(error.to_string()))
}

fn terminate_group(child: &mut std::process::Child, pid: Pid) -> Result<(), ProcessError> {
    let _ = kill_process_group(pid, Signal::TERM);
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if child
            .try_wait()
            .map_err(|error| ProcessError::OperatingSystem(error.to_string()))?
            .is_some()
        {
            let _ = kill_process_group(pid, Signal::KILL);
            return Ok(());
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = kill_process_group(pid, Signal::KILL);
    child
        .wait()
        .map_err(|error| ProcessError::OperatingSystem(error.to_string()))?;
    Ok(())
}
