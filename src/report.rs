// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use crate::GdbTriageResult;

use std::cmp;

pub struct CrashReport {
    pub headline: String,
    pub backtrace: String,
    pub stackhash: String
}

pub fn format_text_report(triage_result: &GdbTriageResult) -> CrashReport {
    let mut report = CrashReport {
        headline: "".to_string(),
        stackhash: "".to_string(),
        backtrace: "".to_string(),
    };

    let crashing_tid = triage_result.thread_info.current_tid;

    for thread in &triage_result.thread_info.threads {
        if thread.tid == crashing_tid {
            let frames = &thread.backtrace[0..];

            if frames.is_empty() {
                // TODO: warning of empty backtrace
                continue;
            }

            let first_frame = frames.get(0).unwrap();

            let headline = match &first_frame.symbol {
                Some(symbol) => format!("tid {} in {}",
                         crashing_tid, symbol.format()),
                None => format!("tid {} in {:<08x}", crashing_tid, first_frame.address),
            };

            let mut major_hash = md5::Context::new();
            let mut backtrace = String::new();

            for (i, fr) in frames.iter().enumerate() {
                let frame_header = format!("#{:<2} pc {:<08x}", i, fr.address);
                let frame_module = format!("{} {}", frame_header, fr.module);
                let frame_pad = frame_header.len() + 1;

                major_hash.consume(fr.module_address.as_bytes());

                match &fr.symbol {
                    Some(symbol) => {
                        backtrace += &format!("{} ({})\n",
                            frame_module, symbol.format());
                    }
                    _ => {
                        backtrace += &format!("{}\n", frame_module);
                    }
                }

                match &fr.symbol {
                    Some(symbol) => {
                        let file_sym = symbol.format_file();
                        let mut ctx = vec![];

                        if !file_sym.is_empty() {
                            ctx.push(format!("in {}", file_sym));
                        }

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

                                ctx.push(format!("{:.<pad$}:", "", pad=pad));
                                ctx.push(format!("{:>pad$}: {}", lineno, callsite.get(0).unwrap(), pad=pad));
                                ctx.push(format!("{:.<pad$}:", "", pad=pad));
                                ctx.push(format!("{:.<pad$}: }}", "", pad=pad));
                            }
                            None =>  {
                                // we likely only have the function name, but this is printed
                                // before. don't double print
                                if !ctx.is_empty() {
                                    ctx.push(format!("{}", symbol.format_function_prototype()));
                                }
                            }
                        };

                        if !ctx.is_empty() {
                            for line in ctx {
                                backtrace += &format!("{:pad$}", "", pad=frame_pad);
                                backtrace += &format!("{}\n", line);
                            }
                        }
                    }
                    _ => ()
                }
            }

            report.headline = headline;
            report.stackhash = String::from(format!("{:x}", major_hash.compute()));
            report.backtrace = backtrace;
        }
    }

    report
}

