// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//! Process spawning utilities
use async_io::block_on;
use futures_lite::io::AsyncWriteExt;
use smol_timeout::TimeoutExt;
use std::ffi::OsStr;
use std::io::{Result, Error, ErrorKind};
use std::process::{Command, ExitStatus, Output};
use async_process::unix::CommandExt;
use std::time::Duration;

#[derive(Debug)]
pub struct ChildResult {
    pub stdout: String,
    pub stderr: String,
    pub status: ExitStatus,
}

/// Execute a `command` with `args` and capture the output as a String
pub fn execute_capture_output<S: AsRef<OsStr>>(command: &str, args: &[S]) -> Result<ChildResult> {
    let output = Command::new(command).args(args).output()?;

    Ok(ChildResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        status: output.status,
    })
}

/// Send SIGTERM to a process
fn kill_gracefully(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
}

/// Send SIGKILL to a process
fn kill_forcefully(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

/// Mask certainy signals when executing subprocesses
// SAFETY: simple signal handling
unsafe fn pre_execute() {
    let mut set: libc::sigset_t = core::mem::MaybeUninit::uninit().assume_init();

    // GDB spawned under a controlling TTY will inherit it. This means it will also receive
    // SIGWINCH signals, which can prevent it from properly returning piped output to the parent
    // With this, we don't need to create a dedicated PTY and session
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, libc::SIGWINCH);
    // It will also receive user Ctrl+C signals which is not desired as this can create random
    // triage errors during GDB script processing
    libc::sigaddset(&mut set, libc::SIGINT);
    libc::sigprocmask(libc::SIG_BLOCK, &mut set, core::ptr::null_mut());
}

/// Execute a `command` with `args` while enforcing a timeout of `timeout_ms`, after which the
/// target process is killed. `input` can be passed if input is to be given to the process via
/// STDIN
pub fn execute_capture_output_timeout<S: AsRef<OsStr>>(
    command: &str,
    args: &[S],
    timeout_ms: u64,
    input: Option<Vec<u8>>
) -> Result<ChildResult> {
    let output: Output = block_on(async {
        // SAFETY: only pre_exec call back is unsafe
        let mut cmd = if input.is_none() {
            unsafe {
                async_process::Command::new(command)
                    .stdin(async_process::Stdio::null())
                    .stdout(async_process::Stdio::piped())
                    .stderr(async_process::Stdio::piped())
                    .pre_exec(|| Ok(pre_execute()) )
                    .args(args)
                    .spawn()
            }
        } else {
            unsafe {
                async_process::Command::new(command)
                    .stdin(async_process::Stdio::piped())
                    .stdout(async_process::Stdio::piped())
                    .stderr(async_process::Stdio::piped())
                    .pre_exec(|| Ok(pre_execute()) )
                    .args(args)
                    .spawn()
            }
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
