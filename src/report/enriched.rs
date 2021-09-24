// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use serde::{Deserialize, Serialize};

use super::sanitizer::*;
use crate::gdb_triage::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct CrashBucketInfo {
    /// What is the stringified output from the bucketing function
    pub strategy_result: String,
    /// What hashing or other function was used to identify a crash
    pub bucket_strategy: String,
    /// What stringified inputs were used as input to the bucketing function
    pub inputs: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AddressView {
    /// The raw numbered value. Should be enough size to hold addresses for the architecture
    pub r: u64,
    /// The architecture dependent formatting of this address
    pub f: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedInstructionContext {
    /// The address of the instruction
    pub address: AddressView,
    /// The raw instruction string taken from the debugging backend
    pub insn: String,
    /// AFLTriage's architecture independent guess as to which registers were referenced
    pub referenced_regs: Option<Vec<GdbRegister>>,
    // TODO: support memory references?
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedSourceContext {
    /// The source file
    pub file: String,
    /// The source line
    pub line_no: u64,
    /// The raw source code
    pub source: String,
    /// AFLTriage's language independent guess as to which variables were referenced
    pub references: Option<Vec<GdbVariable>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedThreadInfo {
    /// Frames extracted from a thread's backtrace
    pub frames: Vec<EnrichedFrameInfo>,
    /// Registers may be collected during debugger backtracing
    /// Order is based on the debugging backend
    pub regs: Option<Vec<GdbRegister>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrichedTriageInfo {
    /// A summary of the triage in sentence form
    pub summary: String,
    /// A very terse summary without whitespace
    pub terse_summary: String,
    /// Information on the crash's bucket information, if any
    pub bucket: Option<CrashBucketInfo>,
    /// Platform dependent information as to why the target stopped
    // TODO: make this agnostic to debugging backend/platform
    pub stop_info: GdbStopInfo,
    /// The frame which AFLTriage believes the crash originated
    /// If sanitizer reports cause a crash, AFLTriage will skip initial
    /// sanitizer frames to provide a better estimate of the crash location.
    /// May not always be the most accurate as there are heuristics involved
    /// This is ID indexes the faulting thread's frames
    pub faulting_frame_id: u32,
    /// A stringified function name or address where the fault was believed to occur
    pub faulting_function: String,
    /// The thread that caused a fault leading to the target being stopped
    pub faulting_thread: EnrichedThreadInfo,
    /// Sanitizer reports extracted from the target output in reverse order (most recent first)
    /// Currently only the last report is extracted.
    pub sanitizer_reports: Vec<SanitizerReport>,
    /// Raw output from the target, if enabled
    pub target_output: Option<EnrichedTargetOutput>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedTargetOutput {
    pub stdout: String,
    pub stderr: String,
    /// If a limit was placed on the lines emitted
    pub max_lines: Option<u64>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedFrameInfo {
    /// A summary of the frame using the below fields
    pub summary: String,
    /// The address of the frame. For the first frame in a backtrace this is the stopping point.
    /// For all other frames, this is the address where a new frame was created (e.g. after a call).
    pub address: AddressView,
    /// The address relative to the executable module
    pub relative_address: AddressView,
    /// A file path or best-effort name of the module where the address lies
    pub module: String,
    /// An opinionated, uniquely identifiable (within a process) formatting of module and address
    pub module_address: String,
    /// Symbol information for the frame's function, if available
    pub symbol: Option<GdbSymbol>,
    /// One or more instructions that were collected for this frame.
    pub instruction_context: Option<Vec<EnrichedInstructionContext>>,
    /// One or more lines of source that were collected for this frame.
    pub source_context: Option<Vec<EnrichedSourceContext>>,
}
