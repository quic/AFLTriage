// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use async_io::block_on;
use smol_timeout::TimeoutExt;
use std::ffi::OsStr;
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::process::{Command, ExitStatus, Output};
use std::time::Duration;

#[derive(Debug)]
pub struct ChildResult {
    pub stdout: String,
    pub stderr: String,
    pub status: ExitStatus,
}

pub fn execute_capture_output<S: AsRef<OsStr>>(command: &str, args: &[S]) -> Result<ChildResult> {
    let output = Command::new(command).args(args).output()?;

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

pub fn execute_capture_output_timeout<S: AsRef<OsStr>>(
    command: &str,
    args: &[S],
    timeout_ms: u64,
) -> Result<ChildResult> {
    let output: Output = block_on(async {
        let cmd = async_process::Command::new(command)
            .stdin(async_process::Stdio::null())
            .stdout(async_process::Stdio::piped())
            .stderr(async_process::Stdio::piped())
            .args(args)
            .spawn()?;

        let pid = cmd.id();
        let output = cmd.output();

        let result = output
            .timeout(Duration::from_millis(timeout_ms))
            .await
            .map_or_else(
                || {
                    // this is racy, but its honestly the best we can do without crazy logic
                    kill_gracefully(pid as i32);
                    Err(Error::new(ErrorKind::TimedOut, "Process exceeded timeout"))
                },
                |r| r,
            );

        result
    })?;

    Ok(ChildResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        status: output.status,
    })
}
