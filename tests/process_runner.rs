#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use codex_linux_packager::process::{ProcessSpec, run_bounded, run_bounded_observing_timeout};

#[test]
fn terminates_a_process_group_when_output_exceeds_the_bound() {
    let specification = ProcessSpec {
        program: PathBuf::from("/usr/bin/yes"),
        arguments: Vec::<OsString>::new(),
        working_directory: PathBuf::from("/"),
        environment: BTreeMap::new(),
        timeout: Duration::from_secs(5),
        maximum_output_bytes: 1024,
    };

    let error = run_bounded(&specification).expect_err("unbounded output must terminate");

    assert!(error.to_string().contains("output"));
}

#[test]
fn terminates_a_process_group_at_the_wall_clock_deadline() {
    let specification = ProcessSpec {
        program: PathBuf::from("/usr/bin/sleep"),
        arguments: vec![OsString::from("10")],
        working_directory: PathBuf::from("/"),
        environment: BTreeMap::new(),
        timeout: Duration::from_millis(50),
        maximum_output_bytes: 1024,
    };

    let error = run_bounded(&specification).expect_err("deadline must terminate");

    assert!(error.to_string().contains("timeout"));
}

#[test]
fn an_expected_deadline_can_be_observed_without_losing_bounded_output() {
    let specification = ProcessSpec {
        program: PathBuf::from("/usr/bin/sleep"),
        arguments: vec![OsString::from("10")],
        working_directory: PathBuf::from("/"),
        environment: BTreeMap::new(),
        timeout: Duration::from_millis(50),
        maximum_output_bytes: 1024,
    };

    let outcome = run_bounded_observing_timeout(&specification).expect("observable timeout result");

    assert!(outcome.timed_out);
    assert!(outcome.output.stdout.is_empty());
    assert!(outcome.output.stderr.is_empty());
}
