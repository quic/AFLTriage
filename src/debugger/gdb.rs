// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//! GNU Debugger (GDB) triage functionality
//!
//! AFLTriage heavily leans on GDB 7.10 and above to collect crash context. This includes memory,
//! registers, stack traces, along with symbol and debugging information. GDB acts as an
//! abstraction layer between AFLTriage and the quirks of individual platforms, architectures, and
//! executable formats. To effectively extract context from GDB, AFLTriage uses the GDBTriage
//! python script (see `res/GDBTriage.py`) to cannonicalize and serialize the data into JSON.
//! Unlike previous triaging tools which just print a bunch of output from GDB and call it a day,
//! AFLTriage's JSON focus helps it (and its users) avoid fragile string parsing. While GDBTriage
//! was made for AFLTriage it can be used independently.
//!
//! At build time GDBTriage.py is *embedded* into the AFLTriage binary as a resource. This allows
//! the final AFLTriage binary to be portable between systems without having to worry about using
//! an installer. At run time, AFLTriage will take this file (which is just a string in the binary)
//! and write to a temporary file in /tmp. This file path will then be provided to GDB as a script
//! to load. This script will provide the GDB command `gdbtriage` is executed after running the
//! target. This script will return a JSON result (AFLTriage refers to this as `rawjson`) with
//! triage information or an error if, for instance, the target exited without a crash.
//! This rawjson is parsed and then enriched by AFLTriage into its typical json output format.
//!
//! Regarding how GDB is invoked, it is run using the `--batch` mode, meaning that it will spawn,
//! execute all commands provided to it via command line, and then exit, all in one shot. This
//! means AFLTriage can get away with just controlling GDB with arguments instead of a more
//! complicated, interactive focused interface like [GDB/MI (Machine
//! interface)](https://sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI.html). This is difficult to
//! achieve as GDB's STDOUT and STDERR outputs are intermingled with debugging output and child
//! output. AFLTriage uses some tricks to delimit the output appropriately, avoiding the need to
//! create a dedicated PTY for GDB.
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::os::unix::process::ExitStatusExt;

use crate::util::shell_join;
use crate::process;
use crate::platform::linux::signal_to_string;

#[doc(hidden)]
/// The built-in GDBTriage python script
const INTERNAL_TRIAGE_SCRIPT: &[u8] = include_bytes!("./res/GDBTriage.py");

/// Symbol information for frame
#[derive(Debug, Serialize, PartialEq, Deserialize)]
pub struct GdbSymbol {
    /// The demangled function name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// The line of the start of the function
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_line: Option<i64>,
    /// A mangled function name, if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mangled_function_name: Option<String>,
    /// A function's type signature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_signature: Option<String>,
    /// One or more lines of code surrounding the frame address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callsite: Option<Vec<String>>,
    /// The file of the frame address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The source line of the frame address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<i64>,
    /// Frame function arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<Rc<GdbVariable>>>,
    /// Frame local variables
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locals: Option<Vec<Rc<GdbVariable>>>,
}

impl GdbSymbol {
    /// Short hand for [GdbSymbol::format_short]
    pub fn format(&self) -> String {
        self.format_short()
    }

    /// Just a function name or blank if not available
    pub fn format_short(&self) -> String {
        self.function_name
            .as_ref()
            .unwrap_or(&String::from(""))
            .to_string()
    }

    /// A C-like function prototype
    pub fn format_function_prototype(&self) -> String {
        let return_type = match &self.function_signature {
            Some(rv) => match rv.find(' ') {
                Some(pos) => rv[..=pos].to_string(),
                None => "".to_string(),
            },
            None => "".to_string(),
        };

        let args = self.args.as_ref().map_or_else(
            || String::from(""),
            |args| {
                args.iter()
                    .map(|x| x.format_arg())
                    .collect::<Vec<String>>()
                    .join(", ")
            },
        );

        return format!("{}{}({})", return_type, self.format_short(), args);
    }

    /// A C-like function call
    pub fn format_function_call(&self) -> String {
        let args = self.args.as_ref().map_or_else(
            || String::from("???"),
            |args| {
                args.iter()
                    .map(|x| x.name.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ")
            },
        );

        return format!("{}({})", self.format_short(), args);
    }

    /// Display like file:line
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

/// GDB variable information
#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GdbVariable {
    /// The GDB type of the variable
    pub r#type: String,
    /// Variable name
    pub name: String,
    /// The GDB pretty string representation of the variable
    pub value: String,
}

impl GdbVariable {
    /// Format a variable as an argument assignment with explicit cast
    pub fn format_arg(&self) -> String {
        format!("{} = ({}){}", self.name, self.r#type, self.value)
    }

    /// Format a variable in a C-like fashion
    pub fn format_decl(&self) -> String {
        format!("{} {} = {};", self.r#type, self.name, self.value)
    }
}

/// Frame information
#[derive(Debug, Serialize, Deserialize)]
pub struct GdbFrameInfo {
    /// A target-native address
    pub address: u64,
    /// The address relative to the module base
    pub relative_address: u64,
    /// The name of the module. NOTE: can be ??, \[vdso\], \[heap\] or other depending on context.
    /// Taken from Linux /proc/PID/mappings
    pub module: String,
    /// An address-space unique identifier
    pub module_address: String,
    /// GDB symbol information, if present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<Rc<GdbSymbol>>,
}

/// Thread information
#[derive(Debug, Serialize, Deserialize)]
pub struct GdbThread {
    /// The thread's OS ID
    pub tid: i32,
    /// Zero or more stack frames
    pub backtrace: Vec<GdbFrameInfo>,
    /// The current instruction where the thread stopped
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_instruction: Option<String>,
    /// The thread's register set. Registers in the GDB defined order
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registers: Option<Vec<Rc<GdbRegister>>>,
}

/// A target register
#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GdbRegister {
    /// Register name
    pub name: String,
    /// The raw register value
    // TODO: what about SIMD registers larger than 64 bits?
    pub value: u64,
    /// A formatted value from GDB
    pub pretty_value: String,
    /// The register's GDB type
    pub r#type: String,
    /// Size in bytes
    pub size: u64,
}

/// The platform-specific stop information
#[derive(Debug, Serialize, Deserialize)]
pub struct GdbStopInfo {
    /// The Linux signal that caused a stop
    pub signal_name: String,
    /// The Linux signal number (`si_signo`)
    pub signal_number: i32,
    /// The Linux signal code (`si_code`)
    pub signal_code: i32,
    /// The faulting address, if relevant (`sigfault.si_addr`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faulting_address: Option<u64>,
}

/// GDB target architecture information
#[derive(Debug, Serialize, Deserialize)]
pub struct GdbArchInfo {
    /// The target address with in bits
    pub address_bits: usize,
    /// GDB's architecture string for the target
    pub architecture: String,
}

/// The stop context information from GDBTriage
#[derive(Debug, Serialize, Deserialize)]
pub struct GdbContextInfo {
    /// Platform-specific stop info
    pub stop_info: GdbStopInfo,
    /// Architecture information
    pub arch_info: GdbArchInfo,
    /// The primary (or faulting) thread that caused a process stop
    pub primary_thread: GdbThread,
    /// Other process threads (not currently supported)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_threads: Option<Vec<GdbThread>>,
}

/// The result code from GDBTriage
#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum GdbResultCode {
    SUCCESS,
    ERROR_TARGET_NOT_RUNNING,
}

/// The GDBTriage top-level structure
#[derive(Debug, Serialize, Deserialize)]
pub struct GdbJsonResult {
    pub result: GdbResultCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<GdbContextInfo>,
}

/// The top-level AFLTriage structure
#[derive(Debug, Serialize, Deserialize)]
pub struct GdbTriageResult {
    pub response: GdbJsonResult,
    pub child: GdbChildOutput,
}

/// The target's output strings
#[derive(Debug, Serialize, Deserialize)]
pub struct GdbChildOutput {
    pub stdout: String,
    pub stderr: String,
}

/// What type of GDBTriage error occurred
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum GdbTriageErrorKind {
    Command,
    Internal,
    Timeout,
}

/// Information on the GDBTriage error that occurred
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct GdbTriageError {
    pub error_kind: GdbTriageErrorKind,
    pub error: String,
    pub details: Vec<String>,
}

impl GdbTriageError {
    pub fn new(
        error_kind: GdbTriageErrorKind,
        error: &str,
        extra_detail: String,
    ) -> GdbTriageError {
        GdbTriageError {
            error_kind,
            error: error.to_string(),
            details: vec![extra_detail],
        }
    }

    pub fn new_brief(error_kind: GdbTriageErrorKind, error: String) -> GdbTriageError {
        GdbTriageError {
            error_kind,
            error: error,
            details: Vec::new(),
        }
    }

    pub fn new_detailed<S: AsRef<str>>(
        error_kind: GdbTriageErrorKind,
        error: S,
        details: Vec<String>,
    ) -> GdbTriageError {
        GdbTriageError {
            error_kind,
            error: error.as_ref().to_string(),
            details,
        }
    }

    pub fn to_string(&self) -> String {
        if self.details.is_empty() {
            format!("{}", self.error)
        } else if self.details.len() == 1 {
            format!(
                "{}: {}",
                self.error,
                self.details.get(0).unwrap().trim_end(),
            )
        } else {
            let mut msg = format!("{}\n", self.error);

            for (i, line) in self.details.iter().enumerate() {
                msg += &format!("{}: {}\n", i + 1, line.trim_end());
            }

            msg
        }
    }
}

#[doc(hidden)]
macro_rules! vec_of_strings {
    ($($x:expr),*) => (vec![$($x.to_string()),*]);
}

#[doc(hidden)]
struct DbgMarker {
    start: &'static str,
    end: &'static str,
    gdb_start: &'static str,
    gdb_end: &'static str,
}

impl DbgMarker {
    fn extract<'a>(&self, text: &'a str) -> Result<&'a str, String> {
        match text.find(&self.start) {
            Some(mut start_idx) => {
                match text.find(&self.end) {
                    Some(end_idx) => {
                        // assuming its printed as a newline
                        start_idx += self.start.len() + 1;

                        if start_idx <= end_idx {
                            Ok(&text[start_idx..end_idx])
                        } else {
                            Err(String::from("Start marker and end marker out-of-order"))
                        }
                    }
                    None => Err(format!("Could not find {}", self.end)),
                }
            }
            None => Err(format!("Could not find {}", self.start)),
        }
    }
}

// This is a neat trick to cut up the output we get from GDB into parts without having to
// join stderr and stdout into a single stream
// Some versions of GDB don't flush output before starting a child, so explicitly flush
macro_rules! make_gdb_marker {
    ( $string:expr ) => {
        concat!(
            "python [(x.write('",
            $string,
            "\\n'),x.flush()) for x in [sys.stdout, sys.stderr]]"
        )
    };
}

macro_rules! make_marker {
    ( $string:expr ) => {
        DbgMarker {
            start: concat!("----", $string, "_START----"),
            end: concat!("----", $string, "_END----"),
            gdb_start: make_gdb_marker!(concat!("----", $string, "_START----")),
            gdb_end: make_gdb_marker!(concat!("----", $string, "_END----")),
        }
    };
}

lazy_static! {
    #[doc(hidden)]
    static ref MARKER_CHILD_OUTPUT: DbgMarker = make_marker!("AFLTRIAGE_CHILD_OUTPUT");
    #[doc(hidden)]
    static ref MARKER_BACKTRACE: DbgMarker = make_marker!("AFLTRIAGE_BACKTRACE");
}

enum GdbTriageScript {
    #[allow(dead_code)]
    External(PathBuf),
    Internal(tempfile::NamedTempFile),
}

/// Triage crashes using GDB
pub struct GdbTriager {
    triage_script: GdbTriageScript,
    pub gdb_path: String,
}

impl GdbTriager {
    /// Create a new [GdbTriager] using the built-in GDBTriage script
    pub fn new(gdb_path: String) -> GdbTriager {
        let mut triage_script =
            GdbTriageScript::Internal(tempfile::Builder::new().suffix(".py").tempfile().unwrap());

        if let GdbTriageScript::Internal(ref mut tf) = triage_script {
            tf.write_all(INTERNAL_TRIAGE_SCRIPT).unwrap();
        } else {
            panic!("Unsupported script path");
        }

        GdbTriager {
            triage_script,
            gdb_path,
        }
    }

    /// Confirm that the selected GDB executable meets the requirements
    pub fn has_supported_gdb(&self) -> bool {
        let python_cmd = "python import gdb, sys; print('V:'+gdb.execute('show version', to_string=True).splitlines()[0]); print('P:'+sys.version.splitlines()[0].strip())";
        let gdb_args = vec!["--nx", "--batch", "-iex", python_cmd];

        let output = match process::execute_capture_output(&self.gdb_path, &gdb_args) {
            Ok(o) => o,
            Err(e) => {
                log::error!("Failed to execute specified GDB '{}': {}", &self.gdb_path, e);
                return false;
            }
        };

        let decoded_stdout = &output.stdout;
        let decoded_stderr = &output.stderr;

        let version = decoded_stdout
            .find("V:")
            .map(|start_idx| (&decoded_stdout[start_idx + 2..]).lines().next().unwrap());

        let python_version = decoded_stdout
            .find("P:")
            .map(|start_idx| (&decoded_stdout[start_idx + 2..]).lines().next().unwrap());

        if !output.status.success() || version == None || python_version == None {
            log::error!(
                "GDB check failure\nARGS:{}\nSTDOUT: {}\nSTDERR: {}",
                shell_join(&gdb_args),
                decoded_stdout,
                decoded_stderr
            );
            return false;
        }

        log::info!(
            "GDB is working ({} - Python {})",
            version.unwrap(),
            python_version.unwrap()
        );

        true
    }

    /// Execute a target program under GDB and execute GDBTriage to collect crash information, if
    /// any.
    ///
    /// `show_raw_output` will display low-level triaging information which is helpful during debugging
    pub fn triage_program(
        &self,
        prog_args: &[String],
        input_file: Option<&str>,
        show_raw_output: bool,
        timeout_ms: u64,
    ) -> Result<GdbTriageResult, GdbTriageError> {
        let triage_script_path = if let GdbTriageScript::Internal(tf) = &self.triage_script {
            tf.path()
        } else {
            panic!("Unsupported triage script path")
        };

        let gdb_run_command = match input_file {
            // GDB overwrites args in the format (damn you)
            // Using this version of run uses the shell to run the command.
            // Not ideal, but since we don't have a clean TTY for the target, this will have to do
            Some(file) => format!("run {} < {}",
                    shell_join(&prog_args[1..]),
                    shlex::quote(file)
                ),
            None => String::from("run"),
        };

        // TODO: memory limit?
        #[rustfmt::rustfmt_skip]
        let gdb_args = vec_of_strings!(
            "--nx", "--batch",
            // FIXME: index cache is a bit unreliable on earlier GDB versions
            //"-iex", "set index-cache on",
            //"-iex", "set index-cache directory gdb_cache",

            // Make special effort to get target output WITHOUT any GDB logging
            "-iex", "set print inferior-events off",
            // Get detailed python errors
            "-iex", "set python print-stack full",
            // Markers will not print if logging is to /dev/null
            "-ex", MARKER_CHILD_OUTPUT.gdb_start,
            "-ex", "set logging file /dev/null",
            "-ex", "set logging redirect on",
            "-ex", "set logging on",
            "-ex", gdb_run_command,
            "-ex", "set logging redirect off",
            "-ex", "set logging off",
            "-ex", MARKER_CHILD_OUTPUT.gdb_end,
            "-ex", MARKER_BACKTRACE.gdb_start,
            "-x", triage_script_path.to_str().unwrap(),
            "-ex", "gdbtriage",
            "-ex", MARKER_BACKTRACE.gdb_end,
            "--args"
        );

        let gdb_cmdline = &[&gdb_args[..], prog_args].concat();

        // Never write to stdin for GDB as it can pass testcases to the target using "run < FILE"
        let output =
            match process::execute_capture_output_timeout(&self.gdb_path, gdb_cmdline, timeout_ms, None) {
                Ok(o) => o,
                Err(e) => {
                    return if e.kind() == ErrorKind::TimedOut {
                        Err(GdbTriageError::new(
                            GdbTriageErrorKind::Timeout,
                            "Timed out when triaging",
                            e.to_string(),
                        ))
                    } else {
                        Err(GdbTriageError::new(
                            GdbTriageErrorKind::Command,
                            "Failed to execute GDB command",
                            e.to_string(),
                        ))
                    };
                }
            };

        let decoded_stdout = &output.stdout;
        let decoded_stderr = &output.stderr;

        if show_raw_output {
            let gdb_cmd_fmt = shell_join(
                &[std::slice::from_ref(&self.gdb_path), gdb_cmdline]
                    .concat()
            );
            println!("--- RAW GDB BEGIN ---\nPROGRAM CMDLINE: {}\nGDB CMDLINE: {}\nSTDOUT:\n{}\nSTDERR:\n{}\n--- RAW GDB END ---",
                shell_join(&prog_args[..]), gdb_cmd_fmt, decoded_stdout, decoded_stderr);
        }

        if let Some(exit_code) = output.status.code() {
            if exit_code != 0 {
                return Err(GdbTriageError::new_brief(
                    GdbTriageErrorKind::Command,
                    format!("GDB exited with non-zero code {}", exit_code.to_string())
                ));
            }
        }

        // It's not unheard of for GDB itself to crash, OOM, or BUG the kernel...
        if let Some(signal) = output.status.signal() {
            return Err(GdbTriageError::new_brief(
                GdbTriageErrorKind::Command,
                format!("GDB exited via signal {} ({})!",
                    signal_to_string(signal), signal.to_string()
                )
            ));
        }

        let child_output_stdout = match MARKER_CHILD_OUTPUT.extract(decoded_stdout) {
            Ok(output) => output.to_string(),
            Err(e) => {
                return Err(GdbTriageError::new(
                    GdbTriageErrorKind::Command,
                    "Could not extract child STDOUT",
                    e,
                ))
            }
        };

        let child_output_stderr = match MARKER_CHILD_OUTPUT.extract(decoded_stderr) {
            Ok(output) => output.to_string(),
            Err(e) => {
                return Err(GdbTriageError::new(
                    GdbTriageErrorKind::Command,
                    "Could not extract child STDERR",
                    e,
                ))
            }
        };

        let backtrace_output = match MARKER_BACKTRACE.extract(decoded_stdout) {
            Ok(output) => output,
            Err(e) => {
                return Err(GdbTriageError::new(
                    GdbTriageErrorKind::Command,
                    "Failed to get triage JSON from GDB",
                    e,
                ))
            }
        };

        let backtrace_messages = match MARKER_BACKTRACE.extract(decoded_stderr) {
            Ok(output) => output,
            Err(e) => {
                return Err(GdbTriageError::new(
                    GdbTriageErrorKind::Command,
                    "Failed to get triage errors from GDB",
                    e,
                ))
            }
        };

        if backtrace_output.is_empty() && !backtrace_messages.is_empty() {
            return Err(GdbTriageError::new_detailed(
                GdbTriageErrorKind::Command,
                "Triage script emitted errors",
                backtrace_messages.lines().map(str::to_string).collect(),
            ));
        }

        match serde_json::from_str(backtrace_output) {
            Ok(json) => Ok(GdbTriageResult {
                response: json,
                child: GdbChildOutput {
                    stdout: child_output_stdout,
                    stderr: child_output_stderr,
                },
            }),
            Err(e) => Err(GdbTriageError::new(
                GdbTriageErrorKind::Command,
                "Failed to parse triage JSON from GDB",
                e.to_string(),
            )),
        }
    }
}
