// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use std::process::{Command, ExitStatus, Output, Stdio};
use std::ffi::OsStr;
use std::io::{Result, Write};
use smol_timeout::TimeoutExt;
use std::time::Duration;
use std::io::{Error, ErrorKind};
use async_io::{block_on};

#[derive(Debug)]
pub struct ChildResult {
    pub stdout: String,
    pub stderr: String,
    pub status: ExitStatus,
}

pub fn execute_capture_output<S: AsRef<OsStr>>(command: &str, args: &Vec<S>) -> Result<ChildResult> {
    let output = Command::new(command)
            .args(args)
            .output()?;

    Ok(ChildResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        status: output.status,
    })
}

pub fn execute_capture_output_stdin<S: AsRef<OsStr>>(command: &str, args: &Vec<S>, stdin: &str) -> Result<ChildResult> {
    let mut child = Command::new(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(args)
            .spawn()?;

    child.stdin.take().unwrap().write_all(stdin.as_bytes());

    let output: Output = child.wait_with_output()?;

    Ok(ChildResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        status: output.status,
    })
}

fn kill_gracefully(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
}

pub fn execute_capture_output_timeout<S: AsRef<OsStr>>(command: &str, args: &Vec<S>, timeout_ms: u64) -> Result<ChildResult> {
    let output: Output = block_on( async {
        let cmd = async_process::Command::new(command)
            .stdin(async_process::Stdio::null())
            .stdout(async_process::Stdio::piped())
            .stderr(async_process::Stdio::piped())
            .args(args)
            .spawn()?;

        let pid = cmd.id();
        let output = cmd.output();

        let result = match output.timeout(Duration::from_millis(timeout_ms)).await {
            Some(res) => res,
            None => {
                // this is racy, but its honestly the best we can do without crazy logic
                kill_gracefully(pid as i32);
                Err(Error::new(ErrorKind::TimedOut, "Process exceeded timeout"))
            }
        };

        result
    })?;

    Ok(ChildResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        status: output.status,
    })
}
