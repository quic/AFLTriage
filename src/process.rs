// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use std::process::{Command, Output};
use std::ffi::OsStr;
use std::io::Result;

pub fn execute_capture_output<S: AsRef<OsStr>>(command: &str, args: &Vec<S>) -> Result<Output> {
    let output = Command::new(command)
            .args(args)
            .output()?;

    Ok(output)
}
