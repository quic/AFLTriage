// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//! AFLTriage's native "Enriched" report type.
//!
//! Enriched reports start with [EnrichedTriageInfo], which contains a crash summary, stop
//! information, faulting frame info, sanitizer reports (if any), and target output.
//!
//! This report style can be serizalized to JSON.
use std::collections::HashSet;
use std::rc::Rc;
use super::sanitizer::*;
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::HashMap;
use crate::debugger::gdb::*;
use crate::ReportOptions;
use crate::util;
use crate::platform::linux::si_code_to_string;

lazy_static! {
    static ref R_CIDENT: Regex = Regex::new(r#"[_a-zA-Z][_a-zA-Z0-9]{0,30}"#).unwrap();
}

/// A container for target addresses
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

/// Context information for a single target instruction
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedInstructionContext {
    /// The address of the instruction
    pub address: AddressView,
    /// The raw instruction string taken from the debugging backend
    pub insn: String,
    /// AFLTriage's architecture independent guess as to which registers were referenced
    // TODO HELPWANTED: https://github.com/serde-rs/json/issues/513 do this
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referenced_regs: Option<Vec<Rc<GdbRegister>>>,
    // TODO: support memory references?
}

/// Context information for a single source line
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedSourceContext {
    /// The source file
    pub file: String,
    /// The source line
    pub line_no: usize,
    /// The raw source code
    pub source: String,
    /// AFLTriage's language independent guess as to which variables were referenced
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<Rc<GdbVariable>>>,
}

/// Triage information for a single target thread
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedThreadInfo {
    /// Frames extracted from a thread's backtrace
    pub frames: Vec<EnrichedFrameInfo>,
    /// Registers may be collected during debugger backtracing
    /// Order is based on the debugging backend
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registers: Option<Vec<Rc<GdbRegister>>>,
    /// One or more instructions that were collected for this thread
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_context: Option<Vec<EnrichedInstructionContext>>,
}

/// Output from the target
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedTargetOutput {
    pub stdout: String,
    pub stderr: String,
}

/// Information for a single target thread's stack frame
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<Rc<GdbSymbol>>,
    /// One or more lines of source that were collected for this frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_context: Option<Vec<EnrichedSourceContext>>,
}

/// Linux stop information for a target thread
#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faulting_address: Option<AddressView>,
}

/// The top-level container for crash triage information
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrichedTriageInfo {
    /// A summary of the triage in sentence form
    pub summary: String,
    /// A very terse summary without whitespace
    pub terse_summary: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitizer_reports: Option<Vec<SanitizerReport>>,
    /// Raw output from the target, if enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_output: Option<EnrichedTargetOutput>,
}

/// With [ReportOptions] `opt` translate raw debugger triage information ([GdbTriageResult]) into
/// the native [EnrichedTriageInfo] format.
pub fn enrich_triage_info(opt: &ReportOptions, triage_result: &GdbTriageResult) -> Result<EnrichedTriageInfo, &'static str> {
    let ctx_info: &GdbContextInfo = triage_result.response.context.as_ref().unwrap();
    let arch_info: &GdbArchInfo = &ctx_info.arch_info;
    let primary_thread = &ctx_info.primary_thread;
    let frames = &primary_thread.backtrace[0..];

    if frames.is_empty() {
        return Err("Backtrace is empty!")
    }

    let stop_info = build_stop_info(arch_info, &ctx_info.stop_info);

    let faulting_thread = build_thread_info(arch_info, primary_thread);
    let sanitizer_reports = sanitizer_report_extract(&triage_result.child.stderr).map(|r| vec![r]);
    let faulting_sanitizer_report = sanitizer_reports.as_ref()
        .map(|reports| reports.get(0)).flatten();

    let faulting_frame_idx = sanitizer_reports.as_ref()
        .map(|s| find_faulting_frame(&faulting_thread, s)).unwrap_or(0);
    let faulting_frame = &faulting_thread.frames[faulting_frame_idx];
    let faulting_function = faulting_frame.symbol.as_ref()
        .map(|s| s.format()).unwrap_or(faulting_frame.address.f.to_string());

    let target_output = if opt.show_child_output {
        Some(build_target_output(opt, &triage_result.child, &sanitizer_reports))
    } else {
        None
    };

    let summary;
    let terse_summary;

    // Build sanitizer report
    match &faulting_sanitizer_report {
        Some(san) => {
            let op = if san.operation.is_empty() {
                terse_summary =
                    format!("{}_{}_{}", san.name_prefer_short(), san.stop_reason, faulting_function);

                "".to_string()
            } else {
                terse_summary = format!(
                    "{}_{}_{}_{}",
                    san.name_prefer_short(), san.stop_reason, san.operation, faulting_function
                );

                format!(" after a {}", san.operation)
            };

            summary = format!(
                "{} detected {} in {}{} leading to {}",
                san.name_prefer_short(), san.stop_reason, faulting_function, op, stop_info.summary
            );
        }
        None => {
            let fault_address = match &stop_info.faulting_address {
                Some(addr) => format!(" due to a fault at or near {}", addr.f),
                None => "".to_string(),
            };

            summary = format!(
                "CRASH detected in {}{} leading to {}",
                faulting_function, fault_address, stop_info.summary,
            );

            terse_summary = format!("{}_{}", stop_info.signal_name, faulting_function);
        }
    }

    Ok(EnrichedTriageInfo {
        summary,
        terse_summary,
        stop_info,
        faulting_frame_idx,
        faulting_function,
        faulting_thread,
        sanitizer_reports,
        target_output,
    })
}

fn build_target_output(opt: &ReportOptions, child: &GdbChildOutput, sanitizer_reports: &Option<Vec<SanitizerReport>>) -> EnrichedTargetOutput {
    let stderr = if let Some(ref reports) = sanitizer_reports {
        // TODO: multiple reports
        if let Some(report) = reports.get(0) {
            child.stderr.replace(&report.body, &format!("<Replaced {} Report>", report.name_prefer_short()))
        } else {
            child.stderr.to_string()
        }
    } else {
        child.stderr.to_string()
    };

    let stdout = if opt.child_output_lines > 0 {
        util::tail_string(&child.stdout, opt.child_output_lines).join("\n")
    } else {
        child.stdout.to_string()
    };

    let stderr = if opt.child_output_lines > 0 {
        util::tail_string(&stderr, opt.child_output_lines).join("\n")
    } else {
        child.stdout.to_string()
    };

    EnrichedTargetOutput {
        stdout,
        stderr,
    }
}

fn find_faulting_frame(thread: &EnrichedThreadInfo, sanitizers: &Vec<SanitizerReport>) -> usize {
    for san in sanitizers.iter() {
        for san_frame in san.frames.iter() {
            for (fr_id, fr) in thread.frames.iter().enumerate() {
                if (fr.address.r + 1) >= *san_frame && (fr.address.r - 1) <= *san_frame {
                    return fr_id;
                }
            }
        }
    }

    0
}

fn build_thread_info(arch_info: &GdbArchInfo, thread: &GdbThread) -> EnrichedThreadInfo {
    let frames: Vec<EnrichedFrameInfo> = thread.backtrace.iter().map(|f| build_frame_info(arch_info, f)).collect();
    let registers = thread.registers.as_ref().map(|d| d.clone());
    let first_insn_ctx = thread.current_instruction.as_ref()
        .map(|i| build_instruction_context(arch_info, &registers, i.to_string(), frames[0].address.r));
    let insnctx = first_insn_ctx.map(|i| vec![i]);

    EnrichedThreadInfo {
        frames,
        registers,
        instruction_context: insnctx,
    }
}

fn build_reference_list<T>(needles: &HashMap<&str, Rc<T>>, haystack: Vec<&str>) -> Option<Vec<Rc<T>>> {
    let mut found: Vec<Rc<T>> = vec![];
    let mut seen: HashSet<&str> = HashSet::new();

    for line in haystack {
        for ident in R_CIDENT.find_iter(line) {
            let name = ident.as_str();
            if needles.contains_key(name) && !seen.contains(name) {
                found.push(Rc::clone(needles.get(name).unwrap()));
                seen.insert(name);
            }
        }
    }

    if found.is_empty() {
        None
    } else {
        Some(found)
    }
}

fn build_instruction_context(arch_info: &GdbArchInfo, regs: &Option<Vec<Rc<GdbRegister>>>, insn: String, addr: u64) -> EnrichedInstructionContext {
    let referenced_regs = if let Some(regs) = regs {
        let reg_map : HashMap<_, _> = regs.iter().map(|v| (v.name.as_str(), Rc::clone(v))).collect();
        build_reference_list(&reg_map, vec![&insn])
    } else {
        None
    };

    EnrichedInstructionContext {
        address: AddressView::new(addr, arch_info.address_bits),
        insn,
        referenced_regs,
    }
}

fn build_source_context(symbol: &Rc<GdbSymbol>) -> Option<Vec<EnrichedSourceContext>> {
    let mut ctx = vec![];

    if symbol.callsite.is_none() || symbol.file.is_none() ||
        symbol.line.is_none() {
        return None
    }

    let lines = symbol.callsite.as_ref().unwrap();
    let file = symbol.file.as_ref().unwrap();
    let start_line = symbol.line.unwrap();
    let locals_map: Option<HashMap<&str, _>> = symbol.locals.as_ref()
        .map(|vars| vars.iter().map(|v| (v.name.as_str(), Rc::clone(v))).collect());
    let args_map: Option<HashMap<&str, _>> = symbol.args.as_ref()
        .map(|vars| vars.iter().map(|v| (v.name.as_str(), Rc::clone(v))).collect());

    for (i, code) in lines.iter().enumerate() {
        let line_no = (start_line as usize) - lines.len() + i + 1;
        let referenced_locals = locals_map.as_ref().map(|m| build_reference_list(m, vec![&code])).flatten();
        let referenced_args = args_map.as_ref().map(|m| build_reference_list(m, vec![&code])).flatten();

        let references = match (referenced_locals, referenced_args) {
            (Some(l), Some(a)) => Some(l.into_iter().chain(a).collect()),
            (l, a) => l.or(a),
        };

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
    let symbol_reduced = fr.symbol.as_ref().map(|s| reduce_debugger_symbol(s));
    let srcctx = fr.symbol.as_ref().map(|s| build_source_context(s)).flatten();

    let summary = fr.symbol.as_ref()
        .map(|d| format!("{} in {} ({})", address.f, d.format(), module))
        .unwrap_or(format!("{} in {}", address.f, module));

    EnrichedFrameInfo {
        summary,
        address,
        relative_address,
        module,
        module_address,
        symbol: symbol_reduced,
        source_context: srcctx,
    }
}

fn reduce_debugger_symbol(symbol: &Rc<GdbSymbol>) -> Rc<GdbSymbol> {
    Rc::new(GdbSymbol {
        function_name: symbol.function_name.clone(),
        function_line: symbol.function_line.clone(),
        mangled_function_name: symbol.mangled_function_name.clone(),
        function_signature: symbol.function_signature.clone(),
        callsite: None,
        file: symbol.file.clone(),
        line: symbol.line.clone(),
        args: symbol.args.clone(),
        locals: None,
    })
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
    use std::path::PathBuf;
    use crate::bucket::{CrashBucketInfo, CrashBucketStrategy};
    use crate::{ReportOptions, ReportEnvelope};
    use pretty_assertions::assert_eq;

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
    fn test_enriched_report() {
        let triage: GdbTriageResult = serde_json::from_str(&load_test("asan_stack_bof.rawjson")).unwrap();
        let mut envelope_value: serde_json::Value = serde_json::from_str(&load_test("asan_stack_bof.json")).unwrap();
        let etriage_golden: EnrichedTriageInfo = serde_json::from_value(
            envelope_value.get_mut("report").unwrap().take()
        ).unwrap();

        let report_options = ReportOptions {
            show_child_output: true,
            child_output_lines: 25,
        };

        let envelope: ReportEnvelope = serde_json::from_value(envelope_value).unwrap();

        assert_eq!(ReportEnvelope {
                        command_line: vec!["./test".into(), "@@".into()],
                        testcase: "test.c".into(),
                        debugger: "gdb".into(),
                        bucket: CrashBucketInfo {
                            inputs: vec![
                              "/lib/x86_64-linux-gnu/libc-2.27.so+0x3efb7".into(),
                              "/lib/x86_64-linux-gnu/libc-2.27.so+0x40921".into(),
                              "/tmp/test (.text)+0xe95eb".into(),
                              "/tmp/test (.text)+0xe6918".into(),
                              "/tmp/test (.text)+0xc8b9d".into(),
                              "/tmp/test (.text)+0xc9388".into(),
                              "test.c:20".into(),
                              "test.c:33".into(),
                            ],
                            strategy: CrashBucketStrategy::afltriage,
                            strategy_result: "e7a73ec00e0f0d990e5a753f8f942622".into(),
                        },
                        report_options: report_options.clone(),
                    }, envelope);

        let etriage = enrich_triage_info(&report_options, &triage).unwrap();

        assert_eq!(etriage_golden, etriage);
    }
}
