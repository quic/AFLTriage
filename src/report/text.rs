// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use crate::gdb_triage::{GdbRegister, GdbContextInfo, GdbTriageResult};
use crate::platform::linux::si_code_to_string;
use crate::util::elide_size;
use super::sanitizer::*;
use regex::Regex;
use std::cmp;
use std::collections::HashSet;

lazy_static! {
    static ref R_CIDENT: Regex = Regex::new(r#"[_a-zA-Z][_a-zA-Z0-9]{0,30}"#).unwrap();
}

#[derive(Debug)]
pub struct CrashReport {
    pub headline: String,
    pub terse_headline: String,
    pub crashing_function: String,
    pub backtrace: String,
    pub crash_context: String,
    pub asan_body: String,
    pub register_info: String,
    pub stackhash: String,
}

pub fn format_text_report(triage_result: &GdbTriageResult) -> CrashReport {
    let mut report = CrashReport {
        headline: "".to_string(),
        terse_headline: "".to_string(),
        crashing_function: "".to_string(),
        stackhash: "".to_string(),
        crash_context: "".to_string(),
        asan_body: "".to_string(),
        register_info: "".to_string(),
        backtrace: "".to_string(),
    };

    let ctx_info: &GdbContextInfo = triage_result.response.context.as_ref().unwrap();
    let primary_thread = &ctx_info.primary_thread;

    let frames = &primary_thread.backtrace[0..];

    if frames.is_empty() {
        // TODO: warning of empty backtrace
        return report;
    }

    let first_frame = &frames[0];

    let sanitizer_report = sanitizer_report_extract(&triage_result.child.stderr);

    let first_interesting_frame = match &sanitizer_report {
        Some(san) => {
            let mut found_frame = None;

            // Try to resolve the most interesting sanitizer frame compared to GDB frames
            // Note that sanitizer backtrace addresses and GDB addresses can be off-by-one, hence the ranged check
            for san_frame in san.frames.iter() {
                for fr in frames.iter() {
                    if (fr.address + 1) >= *san_frame && (fr.address - 1) <= *san_frame {
                        found_frame = Some(fr);
                        break;
                    }
                }

                if found_frame.is_some() {
                    break
                }
            }

            found_frame.unwrap_or(first_frame)
        }
        _ => first_frame,
    };

    report.crashing_function = match &first_interesting_frame.symbol {
        Some(symbol) => symbol.format(),
        // TODO: align to word size, not 8
        None => format!("0x{:<08x}", first_interesting_frame.address),
    };

    let stop_info = &ctx_info.stop_info;
    let signal_info = format!(
        "{} (si_signo={})",
        stop_info.signal_name, stop_info.signal_number
    );
    let signal_code_info = format!(
        "{} (si_code={})",
        si_code_to_string(&stop_info.signal_name, stop_info.signal_code as i8),
        stop_info.signal_code
    );

    match &sanitizer_report {
        Some(san) => {
            let op = if san.operation.is_empty() {
                // TODO: sanitizer name to short name
                report.terse_headline =
                    format!("ASAN_{}_{}", san.stop_reason, report.crashing_function);

                "".to_string()
            } else {
                report.terse_headline = format!(
                    "ASAN_{}_{}_{}",
                    san.stop_reason, san.operation, report.crashing_function
                );

                format!(" after a {}", san.operation)
            };

            report.headline = format!(
                "ASAN detected {} in {}{} leading to {} / {}",
                san.stop_reason, report.crashing_function, op, signal_info, signal_code_info,
            );
        }
        None => {
            let fault_address = match &stop_info.faulting_address {
                Some(addr) => format!(" due to a fault at or near 0x{:<08x}", addr),
                None => "".to_string(),
            };

            report.headline = format!(
                "CRASH detected in {}{} leading to {} / {} ",
                report.crashing_function, fault_address, signal_info, signal_code_info,
            );

            report.terse_headline = format!("{}_{}", stop_info.signal_name, report.crashing_function);
        }
    }

    if let Some(san) = sanitizer_report {
        report.asan_body = san.body;
    }

    let mut major_hash = md5::Context::new();
    let mut backtrace = String::new();

    if let Some(registers) = &primary_thread.registers {
        let mut regpad = 0;
        for reg in registers {
            regpad = std::cmp::max(regpad, reg.name.len());
        }

        for reg in registers {
            let reg_hexpad = reg.size * 2;
            report.register_info += &format!(
                "{:>regpad$} - 0x{:0>reg_hexpad$x} ({})\n",
                reg.name,
                reg.value,
                reg.pretty_value,
                regpad = regpad,
                reg_hexpad = reg_hexpad as usize
            );
        }
    }

    if let Some(insn) = &primary_thread.current_instruction {
        if let Some(registers) = &primary_thread.registers {
            let mut regs_seen = HashSet::new();

            for ident in R_CIDENT.find_iter(insn) {
                for reg in registers {
                    if ident.as_str() == reg.name {
                        regs_seen.insert(reg);
                        //report.crash_context += &format!("{} = 0x{:<08x}\n", reg.name, reg.value);
                        break;
                    }
                }
            }

            let mut regpad = 0;
            for reg in &regs_seen {
                regpad = std::cmp::max(regpad, reg.name.len());
            }

            for reg in &regs_seen {
                let reg_hexpad = reg.size * 2;
                report.crash_context += &format!(
                    "/* Register reference: {:>regpad$} - 0x{:0>reg_hexpad$x} ({}) */\n",
                    reg.name,
                    reg.value,
                    reg.pretty_value,
                    regpad = regpad,
                    reg_hexpad = reg_hexpad as usize
                );
            }
        }

        report.crash_context += &format!(
            "Execution stopped here ==> 0x{:<08x}: {}\n",
            first_frame.address, insn
        );
    }

    for (i, fr) in frames.iter().enumerate() {
        // TODO: align to word size, not 8
        let frame_header = format!("#{:<2} 0x{:<08x}", i, fr.address);
        let frame_pad = frame_header.len() + 1;

        let file_sym = match &fr.symbol {
            Some(symbol) => symbol.format_file(),
            None => "".to_string(),
        };

        // if we have a file symbol with a line, use it for hashing
        if !file_sym.is_empty() && file_sym.contains(':') {
            major_hash.consume(file_sym.as_bytes());
        } else if fr.module != "[stack]" && fr.module != "[heap]" {
            // don't consider the stack or heap for hashing
            major_hash.consume(fr.module_address.as_bytes());
        }

        match &fr.symbol {
            Some(symbol) => {
                backtrace += &format!("{} in {} ({})\n", frame_header, symbol.format(), fr.module);
            }
            _ => {
                backtrace += &format!("{} in {}\n", frame_header, fr.module);
            }
        }

        if let Some(symbol) = &fr.symbol {
            let mut ctx = vec![];

            match &symbol.callsite {
                Some(callsite) => {
                    let lineno = format!("{}", symbol.line.unwrap());
                    let mut pad = lineno.len();

                    match symbol.function_line {
                        Some(line) => {
                            let lineno = format!("{}", line);
                            pad = cmp::max(lineno.len(), pad);
                            ctx.push(format!(
                                "{:>pad$}: {} {{",
                                lineno,
                                symbol.format_function_prototype(),
                                pad = pad
                            ));
                        }
                        None => ctx.push(format!(
                            "{:?<pad$}: {} {{",
                            "",
                            symbol.format_function_prototype(),
                            pad = pad
                        )),
                    }

                    if let Some(locals) = &symbol.locals {
                        let mut locals_left = HashSet::new();

                        for local in locals {
                            locals_left.insert(local);
                        }

                        for code in callsite {
                            if locals_left.is_empty() {
                                break;
                            }

                            for local in locals_left.clone() {
                                // search for all C-like identifiers and compare them
                                // hacky but avoids false positives when checking
                                // locals with single character names
                                for ident in R_CIDENT.find_iter(code) {
                                    if ident.as_str() == local.name {
                                        locals_left.remove(local);

                                        ctx.push(format!(
                                            "{:|<pad$}: /* Local reference: {} */",
                                            "",
                                            elide_size(&local.format_decl(), 200),
                                            pad = pad
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // see if first line of crash context is less than or equal to function start
                    let first_line = (symbol.line.unwrap() as usize) - callsite.len() + 1;

                    if first_line > ((symbol.function_line.unwrap_or(0) + 1) as usize) {
                        ctx.push(format!("{:|<pad$}:", "", pad = pad));
                    }

                    for (i, code) in callsite.iter().enumerate() {
                        let lineno = (symbol.line.unwrap() as usize) - callsite.len() + i + 1;

                        if lineno <= (symbol.function_line.unwrap_or(0) as usize) {
                            continue;
                        }

                        // context always comes before the line
                        ctx.push(format!("{:>pad$}: {}", lineno, code, pad = pad));
                    }

                    ctx.push(format!("{:|<pad$}:", "", pad = pad));
                    ctx.push(format!("{:-<pad$}: }}", "", pad = pad));
                }
                None => {
                    // we likely only have the function name, but this is printed
                    // before. don't double print
                    if !ctx.is_empty() {
                        ctx.push(symbol.format_function_prototype());
                    }
                }
            };

            if !file_sym.is_empty() {
                ctx.push(format!("at {}", file_sym));
            }

            if !ctx.is_empty() {
                for line in ctx {
                    backtrace += &format!("{:pad$}", "", pad = frame_pad);
                    backtrace += &format!("{}\n", line);
                }
                backtrace += &String::from('\n');
            }
        }
    }

    report.stackhash = format!("{:x}", major_hash.compute());
    report.backtrace = backtrace;

    report
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
    fn test_text_report() {
        let json: GdbJsonResult = serde_json::from_str(&load_test("asan_stack_bof.rawjson")).unwrap();
        let triage = GdbTriageResult {
            response: json,
            child: ChildResult {
                stdout: "".into(),
                stderr: "".into(),
                status: ExitStatus::from_raw(0),
            }
        };

        let report = format_text_report(&triage);
        //println!("{:?}", report);
    }
}
