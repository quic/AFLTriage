// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use std::collections::HashSet;
use crate::gdb_triage::{GdbTriageResult, GdbContextInfo};
use crate::util::elide_size;
use crate::platform::linux::si_code_to_string;
use regex::Regex;
use std::cmp;

lazy_static! {
    static ref R_CIDENT: Regex = Regex::new(r#"[_a-zA-Z][_a-zA-Z0-9]{0,30}"#).unwrap();
    static ref R_ASAN_HEADLINE: Regex = Regex::new(
        r#"(?x)
        (?P<pid>=+[0-9]+=+)\s*ERROR:\s*AddressSanitizer:\s*
        (attempting\s)?(?P<reason>[-_A-Za-z0-9]+)[^\r\n]+[\r\n]+
        (?P<operation>[-_A-Za-z0-9]+)?
        "#).unwrap();

    static ref R_ASAN_FIRST_FRAME: Regex = Regex::new(
        r#"#0\s+(?P<frame>0x[a-fA-F0-9]+)"#).unwrap();
}

pub struct CrashReport {
    pub headline: String,
    pub terse_headline: String,
    pub crashing_function: String,
    pub backtrace: String,
    pub crash_context: String,
    pub asan_body: String,
    pub register_info: String,
    pub stackhash: String
}

struct AsanInfo {
    stop_reason: String,
    operation: String,
    first_frame: u64,
    body: String,
}

fn asan_post_process(triage_result: &GdbTriageResult) -> Option<AsanInfo> {
    let asan_match = R_ASAN_HEADLINE.captures(&triage_result.child.stderr);

    if asan_match.is_none() {
        return None
    }

    // cut out the ASAN body from the child's output
    let asan_headline = asan_match.unwrap();
    let asan_start_marker = asan_headline.name("pid").unwrap().as_str();

    // find the bounds of the ASAN print to capture it raw
    let asan_start_pos = asan_headline.get(0).unwrap().start();

    let asan_body = match &triage_result.child.stderr[asan_start_pos+1..].find(asan_start_marker) {
        Some(asan_end_pos) => &triage_result.child.stderr[asan_start_pos..(asan_start_pos+asan_end_pos+asan_start_marker.len()+1)],
        None => "",
    };

    let stop_reason = asan_headline.name("reason").unwrap().as_str().to_string();

    // Try and find the frame where ASAN was triggered from
    // That way we can print a better info message
    let asan_first_frame: u64 = match R_ASAN_FIRST_FRAME.captures(&asan_body) {
        Some(frame) => {
            u64::from_str_radix(&frame.name("frame").unwrap().as_str()[2..], 16).unwrap()
        }
        None => 0
    };

    let operation: &str = match asan_headline.name("operation") {
        Some(op) => {
            if stop_reason != "SEGV" {
                op.as_str()
            } else {
                ""
            }
        }
        _ => "",
    };

    Some(AsanInfo {
        stop_reason,
        operation: operation.to_string(),
        first_frame: asan_first_frame,
        body: asan_body.to_string()
    })
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

    let ctx_info: &GdbContextInfo = triage_result.response.result.as_ref().unwrap();
    let primary_thread = &ctx_info.primary_thread;

    let frames = &primary_thread.backtrace[0..];

    if frames.is_empty() {
        // TODO: warning of empty backtrace
        return report
    }

    let first_frame = frames.get(0).unwrap();

    let asan = asan_post_process(triage_result);

    let first_interesting_frame = match &asan {
        Some(asan) => {
            let mut asan_frame = None;

            // search the backtrace for a closely matching frame
            // note that ASAN backtrace addresses and GDB addresses can be off-by-one, hence
            // the ranged check
            for (i, fr) in frames.iter().enumerate() {
                if (fr.address+1) >= asan.first_frame && (fr.address-1) <= asan.first_frame {
                    asan_frame = Some(fr);
                    break
                }
            }

            asan_frame.unwrap_or(first_frame)
        }
        _ => first_frame,
    };

    report.crashing_function = match &first_interesting_frame.symbol {
        Some(symbol) => format!("{}", symbol.format()),
        // TODO: align to word size, not 8
        None => format!("0x{:<08x}", first_interesting_frame.address),
    };

    let stop_info = &ctx_info.stop_info;
    let signal_info = format!("{} (si_signo={})", stop_info.signal, stop_info.signal_number);
    let signal_code_info = format!("{} (si_code={})",

    si_code_to_string(&stop_info.signal, stop_info.signal_code as i8), stop_info.signal_code);

    match &asan {
        Some(asan) => {
            let op = if asan.operation.is_empty() {
                report.terse_headline = format!("ASAN_{}_{}",
                    asan.stop_reason, report.crashing_function);

                "".to_string()
            } else {
                report.terse_headline = format!("ASAN_{}_{}_{}",
                    asan.stop_reason, asan.operation, report.crashing_function);

                format!(" after a {}", asan.operation)
            };

            report.headline = format!("ASAN detected {} in {}{} leading to {} / {}",
                asan.stop_reason,
                report.crashing_function,
                op,
                signal_info,
                signal_code_info,
            );

        }
        None => {
            let fault_address = match &stop_info.faulting_address {
                Some(addr) => format!(" due to a fault at or near 0x{:<08x}", addr),
                None => "".to_string()
            };

            report.headline = format!("Program received {} / {} in {}{}",
                signal_info,
                signal_code_info,
                report.crashing_function,
                fault_address
            );

            report.terse_headline = format!("{}_{}", stop_info.signal, report.crashing_function);
        }
    }

    if let Some(asan) = asan {
        report.asan_body = asan.body;
    }

    let mut major_hash = md5::Context::new();
    let mut backtrace = String::new();

    if let Some(registers) = &primary_thread.registers {
        for reg in registers {
            report.register_info += &format!("{} - 0x{:<08x} ({})\n", reg.name, reg.value, reg.pretty_value);
        }
    }

    if let Some(insn) = &primary_thread.current_instruction {

        if let Some(registers) = &primary_thread.registers {
            for ident in R_CIDENT.find_iter(insn) {
                for reg in registers {
                    if ident.as_str() == reg.name {
                        report.crash_context += &format!("{} = 0x{:<08x}\n", reg.name, reg.value);
                        break
                    }
                }
            }
        }

        report.crash_context += &format!("Execution stopped here ==> 0x{:<08x}: {}\n", first_frame.address, insn);
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
        if !file_sym.is_empty() && file_sym.contains(":") {
            major_hash.consume(file_sym.as_bytes());
        } else if fr.module != "[stack]" && fr.module != "[heap]" {
            // don't consider the stack or heap for hashing
            major_hash.consume(fr.module_address.as_bytes());
        }

        match &fr.symbol {
            Some(symbol) => {
                backtrace += &format!("{} in {} ({})\n",
                    frame_header, symbol.format(), fr.module);
            }
            _ => {
                backtrace += &format!("{} in {}\n", frame_header, fr.module);
            }
        }

        match &fr.symbol {
            Some(symbol) => {
                let mut ctx = vec![];

                match &symbol.callsite {
                    Some(callsite) => {
                        let lineno = format!("{}", symbol.line.unwrap());
                        let mut pad = lineno.len();

                        match symbol.function_line {
                            Some(line) => {
                                let lineno = format!("{}", line);
                                pad = cmp::max(lineno.len(), pad);
                                ctx.push(format!("{:>pad$}: {} {{",
                                        lineno, symbol.format_function_prototype(), pad=pad));
                            }
                            None => ctx.push(format!("{:?<pad$}: {} {{",
                                        "", symbol.format_function_prototype(), pad=pad)),
                        }

                        let code = callsite.get(0).unwrap();

                        match &symbol.locals {
                            Some(locals) => {
                                let mut locals_left = HashSet::new();

                                for local in locals {
                                    locals_left.insert(local);
                                }

                                for code in callsite {
                                    if locals_left.is_empty() {
                                        break
                                    }

                                    for local in locals_left.clone() {
                                        // search for all C-like identifiers and compare them
                                        // hacky but avoids false positives when checking
                                        // locals with single character names
                                        for ident in R_CIDENT.find_iter(code) {
                                            if ident.as_str() == local.name {
                                                locals_left.remove(local);

                                                ctx.push(format!("{:|<pad$}: /* Local reference: {} */", "",
                                                        elide_size(&local.format_decl(), 200), pad=pad));
                                                break
                                            }
                                        }
                                    }
                                }
                            }
                            _ => ()
                        }

                        ctx.push(format!("{:|<pad$}:", "", pad=pad));
                        for (i, code) in callsite.iter().enumerate() {
                            // context always comes before the line
                            ctx.push(format!("{:>pad$}: {}",
                                    (symbol.line.unwrap() as usize)-callsite.len()+i+1, code, pad=pad));
                        }
                        ctx.push(format!("{:|<pad$}:", "", pad=pad));
                        ctx.push(format!("{:-<pad$}: }}", "", pad=pad));
                    }
                    None =>  {
                        // we likely only have the function name, but this is printed
                        // before. don't double print
                        if !ctx.is_empty() {
                            ctx.push(format!("{}", symbol.format_function_prototype()));
                        }
                    }
                };

                if !file_sym.is_empty() {
                    ctx.push(format!("at {}", file_sym));
                }

                if !ctx.is_empty() {
                    for line in ctx {
                        backtrace += &format!("{:pad$}", "", pad=frame_pad);
                        backtrace += &format!("{}\n", line);
                    }
                    backtrace += &format!("\n");
                }
            }
            _ => ()
        }
    }

    report.stackhash = String::from(format!("{:x}", major_hash.compute()));
    report.backtrace = backtrace;

    report
}
