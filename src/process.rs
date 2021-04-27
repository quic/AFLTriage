// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use std::process::{Command, ExitStatus, Output};
use std::ffi::OsStr;
use std::io::Result;

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
