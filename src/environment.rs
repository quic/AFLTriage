// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//! AFLTriage environment variables
//!
//! * `AFLTRIAGE_GDB_PATH` - Set the path to GDB. [default: gdb]
use std::env;

pub struct AfltriageEnv {
    pub gdb_path: String,
}

impl Default for AfltriageEnv {
    fn default() -> Self {
        AfltriageEnv {
            gdb_path: "gdb".into(),
        }
    }
}

pub fn parse_afltriage_env() -> Option<AfltriageEnv> {
    let mut aenv: AfltriageEnv = Default::default();

    for (key, value) in env::vars_os() {
        let key = key.to_string_lossy();

        if key == "AFLTRIAGE_GDB_PATH" {
            aenv.gdb_path = value.to_string_lossy().to_string();
        } else if key.starts_with("AFLTRIAGE_") {
            log::warn!("Potentially misspelled environment variable {}", key);
        }
    }

    Some(aenv)
}
