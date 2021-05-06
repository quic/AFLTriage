// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tempfile;
use std::io::Write;

use crate::process::{self, ChildResult};

const INTERNAL_TRIAGE_SCRIPT: &[u8] = include_bytes!("../gdb/triage.py");

#[derive(Debug, Serialize, PartialEq, Deserialize)]
pub struct GdbSymbol {
    pub function_name: Option<String>,
    pub function_line: Option<i64>,
    pub mangled_function_name: Option<String>,
    pub function_signature: Option<String>,
    pub callsite: Option<Vec<String>>,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub args: Option<Vec<GdbVariable>>,
    pub locals: Option<Vec<GdbVariable>>
}

impl GdbSymbol {
    pub fn format(&self) -> String {
        self.format_short()
    }

    pub fn format_short(&self) -> String {
        return format!("{}", self.function_name.as_ref().unwrap_or(&"".to_string()));
    }

    pub fn format_function_prototype(&self) -> String {
        let return_type = match &self.function_signature {
            Some(rv) => {
                match rv.find(" ") {
                    Some(pos) => rv[..pos+1].to_string(),
                    None => "".to_string(),
                }
            }
            None => "".to_string(),
        };

        let args = if let Some(args) = &self.args {
            args.iter().map(|x| x.format_arg()).collect::<Vec<String>>().join(", ")
        } else {
            "".to_string()
        };

        return format!("{}{}({})", return_type, self.format_short(), args);
    }

    pub fn format_function_call(&self) -> String {
        let args = if let Some(args) = &self.args {
            args.iter().map(|x| x.name.as_str()).collect::<Vec<&str>>().join(", ")
        } else {
            "???".to_string()
        };

        return format!("{}({})", self.format_short(), args);
    }

    pub fn format_file(&self) -> String {
        let mut filename = String::new();

        if let Some(file) = &self.file {
            filename += file;
        }

        if let Some(line) = &self.line {
            filename += &format!(":{}", line);
        }

        filename
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GdbVariable {
    pub r#type: String,
    pub name: String,
    pub value: String
}

impl GdbVariable {
    pub fn format_arg(&self) -> String {
        format!("{} = ({}){}", self.name, self.r#type, self.value)
    }

    pub fn format_decl(&self) -> String {
        format!("{} {} = {};", self.r#type, self.name, self.value)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbFrameInfo {
    pub address: i64,
    pub relative_address: i64,
    pub module: String,
    pub module_address: String,
    pub symbol: Option<GdbSymbol>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbThread {
    pub tid: i32,
    pub backtrace: Vec<GdbFrameInfo>,
    pub current_instruction: Option<String>,
    pub registers: Option<Vec<GdbRegister>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbRegister {
    pub name: String,
    pub value: u64,
    pub pretty_value: String,
    pub r#type: String,
    pub size: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbStopInfo {
    pub signal: String,
    pub signal_number: i32, // si_signo
    pub signal_code: i32, // si_code
    pub faulting_address: Option<u64>, // sigfault.si_addr
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GdbContextInfo {
    pub stop_info: GdbStopInfo,
    pub primary_thread: GdbThread,
    pub other_threads: Option<Vec<GdbThread>>,
}

// can be blank ({}) meaning error or target exited
#[derive(Debug, Serialize, Deserialize)]
pub struct GdbJsonResult {
    pub result: Option<GdbContextInfo>,
}

#[derive(Debug)]
pub struct GdbTriageResult {
    pub response: GdbJsonResult,
    pub child: ChildResult,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct GdbTriageError {
    pub error: String,
    pub details: Vec<String>,
}

impl GdbTriageError {
    pub fn new(error: &str, extra_detail: String) -> GdbTriageError {
        GdbTriageError {
            error: error.to_string(),
            details: vec![extra_detail]
        }
    }

    pub fn new_brief(error: &str) -> GdbTriageError {
        GdbTriageError {
            error: error.to_string(),
            details: Vec::new(),
        }
    }

    pub fn new_detailed(error: &str, details: Vec<String>) -> GdbTriageError {
        GdbTriageError {
            error: error.to_string(),
            details,
        }
    }
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

        // TODO: allow user to select GDB
        GdbTriager { triage_script, gdb: "gdb".to_string() }
    }

    pub fn has_supported_gdb(&self) -> bool {
        let python_cmd = "python import gdb, sys; print('V:'+gdb.execute('show version', to_string=True).splitlines()[0]); print('P:'+sys.version.splitlines()[0].strip())";
        let gdb_args = vec!["--nx", "--batch", "-iex", &python_cmd];

        let output = match process::execute_capture_output(&self.gdb, &gdb_args) {
            Ok(o) => o,
            Err(e) => {
                log::error!("Failed to execute '{}': {}", &self.gdb, e);
                return false
            }
        };

        let decoded_stdout = &output.stdout;
        let decoded_stderr = &output.stderr;

        let version = match decoded_stdout.find("V:") {
            Some(start_idx) => Some((&decoded_stdout[start_idx+2..]).lines().next().unwrap()),
            None => None,
        };
        let python_version = match decoded_stdout.find("P:") {
            Some(start_idx) => Some((&decoded_stdout[start_idx+2..]).lines().next().unwrap()),
            None => None,
        };

        if !output.status.success() || version == None || python_version == None {
            log::error!("GDB sanity check failure\nARGS:{}\nSTDOUT: {}\nSTDERR: {}",
                     gdb_args.join(" "), decoded_stdout, decoded_stderr);
            return false
        }

        log::info!("GDB is working ({} - Python {})",
            version.unwrap(), python_version.unwrap());

        true
    }

    pub fn triage_testcase(&self, prog_args: Vec<String>, show_raw_output: bool) -> Result<GdbTriageResult, GdbTriageError> {
        let triage_script_path = match &self.triage_script  {
            GdbTriageScript::Internal(tf) => tf.path(),
            _ => return Err(GdbTriageError::new_brief("Unsupported triage script path")),
        };

        // TODO: timeout
        // TODO: memory limit
        let gdb_args = vec_of_strings!(
                            "--batch", "--nx",
                            "-iex", "set index-cache on",
                            "-iex", "set index-cache directory gdb_cache",
                            // write the marker to both stdout and stderr as they are not interleaved
                            "-ex", format!("python [x.write('{}\\n') for x in [sys.stdout, sys.stderr]]", &MARKER_CHILD_OUTPUT.start),
                            "-ex", "set logging file /dev/null",
                            "-ex", "set logging redirect on",
                            "-ex", "set logging on",
                            "-ex", "run",
                            "-ex", "set logging redirect off",
                            "-ex", "set logging off",
                            "-ex", format!("python [x.write('{}\\n') for x in [sys.stdout, sys.stderr]]", &MARKER_CHILD_OUTPUT.end),
                            "-ex", format!("python [x.write('{}\\n') for x in [sys.stdout, sys.stderr]]", &MARKER_BACKTRACE.start),
                            "-x", triage_script_path.to_str().unwrap(),
                            "-ex", format!("python [x.write('{}\\n') for x in [sys.stdout, sys.stderr]]", &MARKER_BACKTRACE.end),
                            "--args");

        let output = match process::execute_capture_output(&self.gdb, &[&gdb_args[..], &prog_args[..]].concat()) {
            Ok(o) => o,
            Err(e) => return Err(GdbTriageError::new("Failed to execute GDB command", e.to_string())),
        };

        let decoded_stdout = &output.stdout;
        let decoded_stderr = &output.stderr;

        if show_raw_output {
            println!("--- RAW GDB BEGIN ---\nGDB ARGS: {}\nPROGRAM ARGS: {}\nSTDOUT:\n{}\nSTDERR:\n{}\n--- RAW GDB END ---",
                gdb_args[..].join(" "), prog_args[..].join(" "), decoded_stdout, decoded_stderr);
        }

        let child_output_stdout = match extract_marker(decoded_stdout, &MARKER_CHILD_OUTPUT) {
            Ok(output) => output.to_string(),
            Err(e) => return Err(GdbTriageError::new("Could not extract child STDOUT", e.to_string())),
        };

        let child_output_stderr = match extract_marker(decoded_stderr, &MARKER_CHILD_OUTPUT) {
            Ok(output) => output.to_string(),
            Err(e) => return Err(GdbTriageError::new("Could not extract child STDERR", e.to_string())),
        };

        let backtrace_output = match extract_marker(decoded_stdout, &MARKER_BACKTRACE) {
            Ok(output) => output,
            Err(e) => return Err(GdbTriageError::new("Failed to get triage JSON from GDB", e.to_string())),
        };

        let backtrace_messages = match extract_marker(decoded_stderr, &MARKER_BACKTRACE) {
            Ok(output) => output,
            Err(e) => return Err(GdbTriageError::new("Failed to get triage errors from GDB", e.to_string())),
        };

        if backtrace_output.is_empty() {
            if !backtrace_messages.is_empty() {
                return Err(GdbTriageError::new_detailed("Triage script emitted errors", backtrace_messages.lines().map(str::to_string).collect()))
            }
        }

        let backtrace_json = match self.parse_response(backtrace_output) {
            Ok(json) => return Ok(GdbTriageResult {
                response: json,
                child: ChildResult {
                    stdout: child_output_stdout,
                    stderr: child_output_stderr,
                    status: output.status,
                },
            }),
            Err(e) => return Err(GdbTriageError::new("Failed to parse triage JSON from GDB", e.to_string())),
        };
    }

    fn parse_response(&self, resp: &str) -> serde_json::Result<GdbJsonResult> {
        serde_json::from_str(resp)
    }
}
