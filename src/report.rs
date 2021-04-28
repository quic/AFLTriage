// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use std::collections::HashSet;
use crate::GdbTriageResult;
use crate::util::elide_size;
use regex::Regex;
use std::cmp;

lazy_static! {
    static ref R_CIDENT: Regex = Regex::new(r#"[_a-zA-Z][_a-zA-Z0-9]{0,30}"#).unwrap();
}

pub struct CrashReport {
    pub headline: String,
    pub crashing_function: String,
    pub backtrace: String,
    pub stackhash: String
}

pub fn format_text_report(triage_result: &GdbTriageResult) -> CrashReport {
    let mut report = CrashReport {
        headline: "".to_string(),
        crashing_function: "".to_string(),
        stackhash: "".to_string(),
        backtrace: "".to_string(),
    };

    let crashing_tid = triage_result.thread_info.current_tid;

    for thread in &triage_result.thread_info.threads {
        if thread.tid != crashing_tid {
            continue
        }

        let frames = &thread.backtrace[0..];

        if frames.is_empty() {
            // TODO: warning of empty backtrace
            continue;
        }

        let first_frame = frames.get(0).unwrap();

        report.crashing_function = match &first_frame.symbol {
            Some(symbol) => format!("{}", symbol.format()),
            // TODO: align to word size, not 8
            None => format!("0x{:<08x}", first_frame.address),
        };

        report.headline = format!("tid {} in {}", crashing_tid, report.crashing_function);

        let mut major_hash = md5::Context::new();
        let mut backtrace = String::new();

        for (i, fr) in frames.iter().enumerate() {
            // TODO: align to word size, not 8
            let frame_header = format!("#{:<2} {:<08x}", i, fr.address);
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
    }

    report
}

