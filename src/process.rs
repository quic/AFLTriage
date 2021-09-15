// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use async_io::block_on;
use futures_lite::io::AsyncWriteExt;
use smol_timeout::TimeoutExt;
use std::ffi::OsStr;
use std::io::{Result, Error, ErrorKind};
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

fn kill_forcefully(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

pub fn execute_capture_output_timeout<S: AsRef<OsStr>>(
    command: &str,
    args: &[S],
    timeout_ms: u64,
    input: Option<Vec<u8>>
) -> Result<ChildResult> {
    let output: Output = block_on(async {
        let mut cmd = if input.is_none() {
            async_process::Command::new(command)
                .stdin(async_process::Stdio::null())
                .stdout(async_process::Stdio::piped())
                .stderr(async_process::Stdio::piped())
                .args(args)
                .spawn()
        } else {
            async_process::Command::new(command)
                .stdin(async_process::Stdio::piped())
                .stdout(async_process::Stdio::piped())
                .stderr(async_process::Stdio::piped())
                .args(args)
                .spawn()
        }?;

        let pid = cmd.id();

        if let Some(data) = input {
            let mut stdin: async_process::ChildStdin = cmd.stdin.take().unwrap();

            // XXX: this can deadlock
            stdin.write_all(data.as_ref()).await?;
        }

        let output = cmd.output();

        let result = output
            .timeout(Duration::from_millis(timeout_ms))
            .await
            .map_or_else(
                || {
                    // this is racy, but its honestly the best we can do without crazy logic
                    kill_gracefully(pid as i32);

                    // give the child sometime to clean up (with a debugger this means ending the
                    // process tree)
                    std::thread::sleep(std::time::Duration::from_millis(100));

                    // once again very racy
                    kill_forcefully(pid as i32);

                    // wait for the background async_process thread to wait() on the PID
                    // this is also pretty racy
                    std::thread::sleep(std::time::Duration::from_millis(100));

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
