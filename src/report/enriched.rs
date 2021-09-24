// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use std::cmp;
use std::collections::HashSet;
use std::rc::Rc;
use super::sanitizer::*;
use serde::{Deserialize, Serialize};
use regex::Regex;
use crate::gdb_triage::*;
use crate::platform::linux::si_code_to_string;

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
    /// The size of the address in bits
    pub s: usize,
}

impl AddressView {
    fn new(r: u64, s: usize) -> AddressView {
        AddressView {
            r,
            f: format!("0x{:0>hexpad$x}", r, hexpad=(s/8)*2),
            s,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedInstructionContext {
    /// The address of the instruction
    pub address: AddressView,
    /// The raw instruction string taken from the debugging backend
    pub insn: String,
    /// AFLTriage's architecture independent guess as to which registers were referenced
    pub referenced_regs: Option<Vec<Rc<GdbRegister>>>,
    // TODO: support memory references?
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedSourceContext {
    /// The source file
    pub file: String,
    /// The source line
    pub line_no: usize,
    /// The raw source code
    pub source: String,
    /// AFLTriage's language independent guess as to which variables were referenced
    pub references: Option<Vec<Rc<GdbVariable>>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedThreadInfo {
    /// Frames extracted from a thread's backtrace
    pub frames: Vec<EnrichedFrameInfo>,
    /// Registers may be collected during debugger backtracing
    /// Order is based on the debugging backend
    pub regs: Option<Vec<Rc<GdbRegister>>>,
    /// One or more instructions that were collected for this thread
    pub instruction_context: Option<Vec<EnrichedInstructionContext>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedTargetOutput {
    pub stdout: String,
    pub stderr: String,
    /// If a limit was placed on the lines emitted
    pub max_lines: Option<usize>,
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
    pub symbol: Option<Rc<GdbSymbol>>,
    /// One or more lines of source that were collected for this frame.
    pub source_context: Option<Vec<EnrichedSourceContext>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrichedLinuxStopInfo {
    /// An summary of the stop info
    pub summary: String,
    /// A friendly name for the signal received (e.g SIGSEGV)
    pub signal_name: String,
    /// The corresponding number of the signal (si_signo). This can be platform dependent
    pub signal_number: i32,
    /// A friendly name for the signal code
    pub signal_code_name: String,
    /// The corresponding number of the signal code (si_code). This can be platform dependent
    pub signal_code: i32,
    /// An optional faulting address (sigfault.si_addr)
    pub faulting_address: Option<AddressView>,
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
    pub stop_info: EnrichedLinuxStopInfo,
    /// The frame index which AFLTriage believes the crash originated
    /// If sanitizer reports cause a crash, AFLTriage will skip initial
    /// sanitizer frames to provide a better estimate of the crash location.
    /// May not always be the most accurate as there are heuristics involved.
    /// Defaults to 0 (first frame) when no better option.
    pub faulting_frame_idx: usize,
    /// A stringified function name or address where the fault was believed to occur
    pub faulting_function: String,
    /// The thread that caused a fault leading to the target being stopped
    pub faulting_thread: EnrichedThreadInfo,
    /// Sanitizer reports extracted from the target output in reverse order (most recent first)
    /// Currently only the last report is extracted.
    pub sanitizer_reports: Option<Vec<SanitizerReport>>,
    /// Raw output from the target, if enabled
    pub target_output: Option<EnrichedTargetOutput>,
}

pub struct ReportOptions {
    output_lines: usize,
    bucket_strategy: String,
}

pub fn enrich_triage_info(opt: &ReportOptions, triage_result: &GdbTriageResult) -> Result<EnrichedTriageInfo, &'static str> {
    let ctx_info: &GdbContextInfo = triage_result.response.context.as_ref().unwrap();
    let arch_info: &GdbArchInfo = &ctx_info.arch_info;
    let primary_thread = &ctx_info.primary_thread;
    let frames = &primary_thread.backtrace[0..];

    if frames.is_empty() {
        return Err("Backtrace is empty!")
    }

    // bucketing is performed after
    let bucket = None;

    let stop_info = build_stop_info(arch_info, &ctx_info.stop_info);

    let faulting_thread = build_thread_info(arch_info, primary_thread);
    let faulting_function = "".into();

    let faulting_frame_idx = 0;
    let sanitizer_reports = None;

    let target_output = None;

    let summary = "".into();
    let terse_summary = "".into();

    Ok(EnrichedTriageInfo {
        summary,
        terse_summary,
        bucket,
        stop_info,
        faulting_frame_idx,
        faulting_function,
        faulting_thread,
        sanitizer_reports,
        target_output,
    })
}

fn build_thread_info(arch_info: &GdbArchInfo, thread: &GdbThread) -> EnrichedThreadInfo {
    let frames: Vec<EnrichedFrameInfo> = thread.backtrace.iter().map(|f| build_frame_info(arch_info, f)).collect();
    let regs = thread.registers.as_ref().map(|d| d.clone());
    let first_insn_ctx = thread.current_instruction.as_ref()
        .map(|i| build_instruction_context(arch_info, &regs, i.to_string(), frames[0].address.r));
    let insnctx = first_insn_ctx.map(|i| vec![i]);

    EnrichedThreadInfo {
        frames,
        regs,
        instruction_context: insnctx,
    }
}

//fn build_reference_list(needles: Vec<&str>, haystack: Vec<&str>) ->

fn build_instruction_context(arch_info: &GdbArchInfo, regs: &Option<Vec<Rc<GdbRegister>>>, insn: String, addr: u64) -> EnrichedInstructionContext {
    let referenced_regs = None;

    EnrichedInstructionContext {
        address: AddressView::new(addr, arch_info.address_bits),
        insn,
        referenced_regs,
    }
}

fn build_source_context(arch_info: &GdbArchInfo, symbol: &Rc<GdbSymbol>) -> Option<Vec<EnrichedSourceContext>> {
    let mut ctx = vec![];

    if symbol.callsite.is_none() || symbol.file.is_none() ||
        symbol.line.is_none() {
        return None
    }

    let lines = symbol.callsite.as_ref().unwrap();
    let file = symbol.file.as_ref().unwrap();
    let start_line = symbol.line.unwrap();

    for (i, code) in lines.iter().enumerate() {
        let line_no = (start_line as usize) - lines.len() + i + 1;
        let references = None;

        ctx.push(EnrichedSourceContext {
            file: file.to_string(),
            line_no,
            source: code.to_string(),
            references,
        })
    }

    Some(ctx)
}

fn build_frame_info(arch_info: &GdbArchInfo, fr: &GdbFrameInfo) -> EnrichedFrameInfo {
    let address = AddressView::new(fr.address, arch_info.address_bits);
    let relative_address = AddressView::new(fr.relative_address, arch_info.address_bits);
    let module = fr.module.to_string();
    let module_address = fr.module_address.to_string();
    // TODO: only include symbols necessary
    let symbol = fr.symbol.as_ref().map(|d| Rc::clone(d));
    let srcctx = symbol.as_ref().map(|s| build_source_context(arch_info, s)).flatten();

    let summary = fr.symbol.as_ref()
        .map(|d| format!("{} in {} ({})", address.f, d.format(), module))
        .unwrap_or(format!("{} in {}", address.f, module));

    EnrichedFrameInfo {
        summary,
        address,
        relative_address,
        module,
        module_address,
        symbol,
        source_context: srcctx,
    }
}

fn build_stop_info(arch: &GdbArchInfo, stop_info: &GdbStopInfo) -> EnrichedLinuxStopInfo {
    let si_code_name = si_code_to_string(&stop_info.signal_name, stop_info.signal_code as i8).into();
    let faulting_address = stop_info.faulting_address.map(|a| AddressView::new(a, arch.address_bits));

    let summary = format!(
        "{} (si_signo={}) / {} (si_code={})",
        stop_info.signal_name,
        stop_info.signal_number,
        si_code_name,
        stop_info.signal_code
    );

    EnrichedLinuxStopInfo {
        summary,
        signal_name: stop_info.signal_name.to_string(),
        signal_number: stop_info.signal_number,
        signal_code_name: si_code_name,
        signal_code: stop_info.signal_code,
        faulting_address,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;
    use std::os::unix::process::ExitStatusExt;
    use crate::gdb_triage::*;
    use crate::process::ChildResult;

    fn load_test(p: &str) -> String {
        std::str::from_utf8(
            &crate::util::read_file_to_bytes(test_path(p).to_str().unwrap()).unwrap()
        ).unwrap().to_string()
    }

    fn test_path(p: &str) -> PathBuf {
        let mut path = PathBuf::from(file!());
        path.pop();
        path.push("res");
        path.push("test_report_text");
        path.push(p);
        path
    }

    #[test]
    fn test_enriched_parse() {
        let json: GdbJsonResult = serde_json::from_str(&load_test("asan_stack_bof.rawjson")).unwrap();
        let triage = GdbTriageResult {
            response: json,
            child: ChildResult {
                stdout: "".into(),
                stderr: "".into(),
                status: ExitStatus::from_raw(0),
            }
        };

        let opt = ReportOptions {
            output_lines: 25,
            bucket_strategy: "default".into(),
        };

        let report = enrich_triage_info(&opt, &triage).unwrap();
        println!("{:#?}", report);
    }
}
