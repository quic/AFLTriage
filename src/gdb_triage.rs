// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use tempfile;
use std::process::{Command, Output};
use std::io::Write;

use crate::process;

const INTERNAL_TRIAGE_SCRIPT: &[u8] = include_bytes!("../gdb/triage.py");

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbSymbol {
    pub function_name: String,
    pub mangled_function_name: String,
    pub function_signature: String,
    pub file: String,
    pub line: i64
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbVariable {
    pub r#type: String,
    pub name: String,
    pub value: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbFrameInfo {
    pub address: i64,
    pub relative_address: i64,
    pub module: String,
    pub pretty_address: String,
    pub symbol: GdbSymbol,
    pub args: Vec<GdbVariable>,
    pub locals: Vec<GdbVariable>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbThread {
    pub tid: i32,
    pub backtrace: Vec<GdbFrameInfo>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbTriageResult {
    pub current_tid: i32,
    pub threads: Vec<GdbThread>,
}

macro_rules! vec_of_strings {
    ($($x:expr),*) => (vec![$($x.to_string()),*]);
}

struct DbgMarker {
    start: String,
    end: String
}

fn make_marker(tag: &str) -> DbgMarker {
    DbgMarker {
        start: String::from(String::from("----") + tag + "_START----"),
        end: String::from(String::from("----") + tag + "_END----"),
    }
}

lazy_static! {
    static ref MARKER_CHILD_OUTPUT: DbgMarker = make_marker("AFLTRIAGE_CHILD_OUTPUT");
    static ref MARKER_BACKTRACE: DbgMarker = make_marker("AFLTRIAGE_BACKTRACE");
}

fn extract_marker<'a>(text: &'a str, marker: &DbgMarker) -> Result<&'a str, String> {
    match text.find(&marker.start) {
        Some(mut start_idx) => {
            match text.find(&marker.end) {
                Some(end_idx) => {
                    // assuming its printed as a newline
                    start_idx += marker.start.len()+1;

                    if start_idx <= end_idx {
                        Ok(&text[start_idx..end_idx])
                    } else {
                        Err(String::from("Start marker and end marker out-of-order"))
                    }
                }
                None => Err(String::from(format!("Could not find {}", marker.end)))
            }
        }
        None => Err(String::from(format!("Could not find {}", marker.start)))
    }
}

enum GdbTriageScript {
    External(PathBuf),
    Internal(tempfile::NamedTempFile)
}

pub struct GdbTriager {
    triage_script: GdbTriageScript,
    gdb: String
}

impl GdbTriager {
    pub fn new() -> GdbTriager {
        let mut triage_script = GdbTriageScript::Internal(
            tempfile::Builder::new()
            .suffix(".py")
            .tempfile().unwrap());

        match triage_script  {
            GdbTriageScript::Internal(ref mut tf) => {
                tf.write_all(INTERNAL_TRIAGE_SCRIPT).unwrap();
            }
            _ => ()
        }

        GdbTriager { triage_script, gdb: "gdb".to_string() }
    }

    pub fn has_supported_gdb(&self) -> bool {
        let python_cmd = "python import gdb, sys; print('V:'+gdb.execute('show version', to_string=True).splitlines()[0]); print('P:'+sys.version.splitlines()[0].strip())";
        let gdb_args = vec!["--nx", "--batch", "-iex", &python_cmd];

        let output = match process::execute_capture_output(&self.gdb, &gdb_args) {
            Ok(o) => o,
            Err(e) => {
                println!("[X] Failed to execute '{}': {}", &self.gdb, e);
                return false
            }
        };

        let decoded_stdout = String::from_utf8_lossy(&output.stdout);
        let decoded_stderr = String::from_utf8_lossy(&output.stderr);

        let version = match decoded_stdout.find("V:") {
            Some(start_idx) => Some((&decoded_stdout[start_idx+2..]).lines().next().unwrap()),
            None => None,
        };
        let python_version = match decoded_stdout.find("P:") {
            Some(start_idx) => Some((&decoded_stdout[start_idx+2..]).lines().next().unwrap()),
            None => None,
        };

        if !output.status.success() || version == None || python_version == None {
            println!("[X] GDB sanity check failure\nARGS:{}\nSTDOUT: {}\nSTDERR: {}",
                     gdb_args.join(" "), decoded_stdout, decoded_stderr);
            return false
        }

        println!("[+] GDB is working ({} - Python {})",
            version.unwrap(), python_version.unwrap());

        true
    }

    pub fn triage_testcase(&self, prog_args: Vec<String>) -> Result<GdbTriageResult, String> {
        let triage_script_path = match &self.triage_script  {
            GdbTriageScript::Internal(tf) => tf.path(),
            _ => return Err(format!("Unsupported triage script path")),
        };

        // TODO: timeout
        // TODO: memory limit
        let gdb_args = vec_of_strings!(
                            "--batch", "--nx",
                            "-iex", "set index-cache on",
                            "-iex", "set index-cache directory gdb_cache",
                            "-ex", format!("echo {}\n", &MARKER_CHILD_OUTPUT.start),
                            "-ex", "set logging file /dev/null",
                            "-ex", "set logging redirect on",
                            "-ex", "set logging on",
                            "-ex", "run",
                            "-ex", "set logging redirect off",
                            "-ex", "set logging off",
                            "-ex", format!("echo {}\n", &MARKER_CHILD_OUTPUT.end),
                            "-ex", format!("echo {}\n", &MARKER_BACKTRACE.start),
                            "-x", triage_script_path.to_str().unwrap(),
                            "-ex", format!("echo {}\n", &MARKER_BACKTRACE.end),
                            "--args");

        // TODO: allow user to select GDB
        let output = match process::execute_capture_output(&self.gdb, &[&gdb_args[..], &prog_args[..]].concat()) {
            Ok(o) => o,
            Err(e) => return Err(format!("Failed to execute command: {}", e)),
        };

        let decoded_stdout = String::from_utf8_lossy(&output.stdout);
        let decoded_stderr = String::from_utf8_lossy(&output.stderr);
        //println!("{}\n{}", decoded_stdout, decoded_stderr);

        let child_output = match extract_marker(&decoded_stdout, &MARKER_CHILD_OUTPUT) {
            Ok(output) => output,
            Err(e) => return Err(format!("Could not extract child output: {}", e)),
        };

        let backtrace_output = match extract_marker(&decoded_stdout, &MARKER_BACKTRACE) {
            Ok(output) => output,
            Err(e) => return Err(format!("Failed to get triage info: {}", e)),
        };

        let backtrace_json = match self.parse_response(backtrace_output) {
            Ok(json) => return Ok(json),
            Err(e) => return Err(format!("Failed to parse triage info: {}", e)),
        };
    }

    fn parse_response(&self, resp: &str) -> serde_json::Result<GdbTriageResult> {
        serde_json::from_str(resp)
    }
}
