// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use crate::{ReportOptions, ReportEnvelope};
use crate::gdb_triage::*;
use crate::report::enriched::*;
use crate::report::sanitizer::*;
use crate::platform::linux::si_code_to_string;
use crate::util::{elide_size, tail_string};

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

pub fn format_text_report_full(opt: &crate::ReportOptions, path: &str, binary_cmdline: &str, report: &CrashReport, triage: &GdbTriageResult) -> String {
    let mut text_report = format!(
        "Summary: {}\nCommand line: {}\nTestcase: {}\nStack hash: {}\n\n",
        report.headline, binary_cmdline, path, report.stackhash
    );

    text_report += &format!("Register info:\n{}\n", report.register_info);
    text_report += &format!("Crash context:\n{}\n", report.crash_context);
    text_report += &format!("Crashing thread backtrace:\n{}\n", report.backtrace);

    if !report.asan_body.is_empty() {
        text_report += &format!("ASAN Report:\n{}\n", report.asan_body);
    }

    let mut format_output = |name: &str, output: &str| {
        if output.is_empty() {
            text_report.push_str(&format!("\nChild {} (no output):\n", name));
        } else if opt.child_output_lines == 0 {
            text_report
                .push_str(&format!("\nChild {} (everything):\n{}\n", name, output));
        } else {
            let lines = tail_string(output, opt.child_output_lines);
            text_report.push_str(&format!(
                "\nChild {} (last {} lines):\n",
                name, opt.child_output_lines
            ));
            for (i, line) in lines.iter().enumerate() {
                if line.is_empty() && i + 1 == lines.len() {
                    break;
                }
                text_report.push_str(&format!("{}\n", line));
            }
        }
    };

    if opt.show_child_output {
        // Dont include the ASAN report duplicated in the child's STDERR
        let stderr = if report.asan_body.is_empty() {
            triage.child.stderr.to_string()
        } else {
            triage
                .child
                .stderr
                .replace(&report.asan_body, "<ASAN Report>")
        };

        format_output("STDOUT", &triage.child.stdout);
        format_output("STDERR", &stderr);
    }

    text_report
}

pub enum TextReportSectionEntry {
    Line(String),
    Section(TextReportSection),
}

pub struct TextReportSection {
    pub section_name: String,
    pub entries: Vec<TextReportSectionEntry>,
}

impl TextReportSection {
    fn new(name: String) -> Self {
        TextReportSection {
            section_name: name,
            entries: vec![],
        }
    }

    fn add(&mut self, entry: TextReportSectionEntry) {
        self.entries.push(entry);
    }

    fn add_line(&mut self, line: String) {
        self.entries.push(TextReportSectionEntry::Line(line));
    }

    fn add_section(&mut self, section: TextReportSection) {
        self.entries.push(TextReportSectionEntry::Section(section));
    }

    // todo indent
    fn format(&self) -> String {
        let mut out = String::new();
        if !self.section_name.is_empty() {
            out += &format!("{}:\n", self.section_name);
        }

        for entry in &self.entries {
            match entry {
                TextReportSectionEntry::Line(l) => {
                    out += &format!("{}\n", l);
                },
                TextReportSectionEntry::Section(s) => {
                    out += &format!("{}\n", s.format());
                },
            }
        }

        out
    }
}

pub struct TextReportSections {
    pub header: TextReportSection,
    pub register_info: TextReportSection,
    pub crash_context: TextReportSection,
    pub backtrace: TextReportSection,
    pub sanitizer_report: TextReportSection,
    pub child_output: TextReportSection,
}

fn build_text_report(einfo: &EnrichedTriageInfo, envelope: &ReportEnvelope) -> TextReportSections {
    let mut header = TextReportSection::new("".into());
    let mut register_info = TextReportSection::new("Register info".into());
    let mut crash_context = TextReportSection::new("Crash context".into());

    let mut backtrace = TextReportSection::new("Crashing thread backtrace".into());
    let mut sanitizer_report = TextReportSection::new("ASAN Report".into()); // TODO asan
    let mut child_output = TextReportSection::new("".into());

    header.add_line(format!(
        "Summary: {}\nCommand line: {}\nTestcase: {}\nStack hash: {}",
        einfo.summary, envelope.command_line.join(" "), envelope.testcase, "e7a73ec00e0f0d990e5a753f8f942622", // TODO
    ));

    build_register_info(einfo, &mut register_info);
    build_instruction_context(einfo, &mut crash_context);
    build_backtrace(einfo, &mut backtrace);

    if let Some(reports) = &einfo.sanitizer_reports {
        // TODO: multiple reports
        if reports.len() > 0 {
            let san_report = &reports[0];
            if !san_report.body.is_empty() {
                sanitizer_report.add_line(san_report.body.to_string());
            }
        }
    }

    if let Some(toutput) = &einfo.target_output {
        build_target_output(toutput, &envelope.report_options, &mut child_output);
    }

    TextReportSections {
        header,
        register_info,
        crash_context,
        backtrace,
        sanitizer_report,
        child_output,
    }
}

fn build_backtrace(einfo: &EnrichedTriageInfo, backtrace: &mut TextReportSection) {
    for (i, fr) in einfo.faulting_thread.frames.iter().enumerate() {

        let mut ctx = vec![];
        let frame_header_p1 = format!("#{:<2} {}", i, fr.address.f);
        let frame_pad = frame_header_p1.len() + 1;
        let frame_header_p2 = fr.symbol.as_ref()
            .map(|s| format!("in {} ({})", s.format(), fr.module))
            .unwrap_or(format!("in {}", fr.module));

        backtrace.add_line(format!("{} {}", frame_header_p1, frame_header_p2));

        if let Some(symbol) = &fr.symbol {
            let file_sym = symbol.format_file();

            if let Some(source_ctx) = &fr.source_context {
                if !source_ctx.is_empty() {
                    let lines = build_source_context(fr, symbol, source_ctx);
                    ctx.extend(lines);
                }
            }

            if !file_sym.is_empty() {
                ctx.push(format!("at {}", file_sym));
            }
        }

        for line in &ctx {
            println!("{}", frame_pad);
            backtrace.add_line(format!("{:pad$}{}", "", line, pad = frame_pad));
        }

        if !ctx.is_empty() {
            backtrace.add_line(format!(""));
        }
    }
}

fn build_source_context(fr: &EnrichedFrameInfo, symbol: &GdbSymbol, source_ctx: &Vec<EnrichedSourceContext>) -> Vec<String> {
    /* NNN: <FUNCTION_PROTOTYPE> {
     * |||: <REF 1>
     * |||: <REF 2>
     * NNN: <BODY1>
     * NNN: <BODY2>
     * |||:
     * ---: }
     */

    let mut ctx = vec![];

    let gutter_width = source_ctx.iter().map(|v| format!("{}", v.line_no).len()).max().unwrap();

    // <FUNCTION_PROTOTYPE>
    match symbol.function_line {
        Some(line) => {
            ctx.push(format!(
                "{:>gutter_width$}: {} {{",
                line,
                symbol.format_function_prototype(),
                gutter_width = gutter_width
            ));
        }
        None => ctx.push(format!(
            "{:?<gutter_width$}: {} {{",
            "",
            symbol.format_function_prototype(),
            gutter_width = gutter_width
        )),
    }

    // see if first line of crash context is less than or equal to function line
    let first_line = source_ctx[0].line_no;
    let function_line = symbol.function_line.unwrap_or(0);

    if first_line > ((function_line + 1) as usize) {
        ctx.push(format!("{:|<gutter_width$}:", "", gutter_width = gutter_width));
    }

    // <REF>
    // Print all unique references
    let mut seen = HashSet::new();

    for src in source_ctx.iter() {
        if let Some(refs) = &src.references {
            for r in refs.iter() {
                if !seen.contains(&r.name) {
                    seen.insert(&r.name);
                    ctx.push(format!(
                        "{:|<gutter_width$}: /* Local reference: {} */",
                        "",
                        elide_size(&r.format_decl(), 200),
                        gutter_width = gutter_width
                    ));
                }
            }
        }
    }


    // <BODY>
    for src in source_ctx.iter() {
        if src.line_no <= (function_line as usize) {
            continue;
        }

        // context always comes before the line
        ctx.push(format!("{:>gutter_width$}: {}", src.line_no, src.source, gutter_width = gutter_width));
    }

    ctx.push(format!("{:|<gutter_width$}:", "", gutter_width = gutter_width));
    ctx.push(format!("{:-<gutter_width$}: }}", "", gutter_width = gutter_width));

    ctx
}

fn build_target_output(toutput: &EnrichedTargetOutput, opt: &ReportOptions, child_output: &mut TextReportSection) {
    let mut section_title = |name: &str, output: &str| -> String {
        if output.is_empty() {
            format!("Child {} (no output)", name)
        } else if opt.child_output_lines == 0 {
            format!("Child {} (everything)", name)
        } else {
            format!("Child {} (last {} lines)", name, opt.child_output_lines)
        }
    };

    let mut stdout = TextReportSection::new(section_title("STDOUT", &toutput.stdout));
    let mut stderr = TextReportSection::new(section_title("STDERR", &toutput.stderr));

    if !toutput.stdout.is_empty() {
        stdout.add_line(toutput.stdout.to_string());
    }
    if !toutput.stderr.is_empty() {
        stderr.add_line(toutput.stderr.to_string());
    }

    child_output.add_section(stdout);
    child_output.add_section(stderr);
}

fn build_register_info(einfo: &EnrichedTriageInfo, register_info: &mut TextReportSection) {
    if let Some(registers) = &einfo.faulting_thread.registers {
        let mut regpad = 0;
        for reg in registers {
            regpad = std::cmp::max(regpad, reg.name.len());
        }

        for reg in registers {
            let reg_hexpad = reg.size * 2;
            register_info.add_line(format!(
                "{:>regpad$} - 0x{:0>reg_hexpad$x} ({})",
                reg.name,
                reg.value,
                reg.pretty_value,
                regpad = regpad,
                reg_hexpad = reg_hexpad as usize
            ));
        }
    }
}

fn build_instruction_context(einfo: &EnrichedTriageInfo, crash_context: &mut TextReportSection) {
    if let Some(insn_ctx) = &einfo.faulting_thread.instruction_context {
        let stopped_here = "Execution stopped here ==> ";

        for (i, insn) in insn_ctx.iter().enumerate() {
            if let Some(ref_regs) = &insn.referenced_regs {
                for reg in ref_regs {
                    let reg_hexpad = reg.size * 2;
                    crash_context.add_line(format!(
                        "/* Register reference: {} - 0x{:0>reg_hexpad$x} ({}) */",
                        reg.name,
                        reg.value,
                        reg.pretty_value,
                        reg_hexpad = reg_hexpad as usize
                    ));
                }
            }

            // FIXME: assumes last instruction context is PC
            if i+1 == insn_ctx.len() {
                crash_context.add_line(format!(
                    "{}{}: {}",
                    stopped_here, insn.address.f, insn.insn,
                ));
            } else {
                crash_context.add_line(format!(
                    "{:pad$}{}: {}",
                    "", insn.address.f, insn.insn, pad=stopped_here.len()
                ));
            }
        }
    }
}

fn format_text_report_new(sections: TextReportSections) -> String {
    let mut report: String = String::new();

    report += &sections.header.format();
    report += "\n";
    report += &sections.register_info.format();
    report += "\n";
    report += &sections.crash_context.format();
    report += "\n";
    report += &sections.backtrace.format();
    report += "\n";
    report += &sections.sanitizer_report.format();
    report += "\n";
    report += &sections.child_output.format();

    // remove all but last newline
    report = report.trim().to_string();
    report += "\n";
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

    fn assert_lines_eq(l: &str, r: &str) {
        let ll: Vec<&str> = l.split("\n").collect();
        let lr: Vec<&str> = r.split("\n").collect();

        for (left, right) in (&ll).iter().zip(&lr) {
            assert_eq!(left, right)
        }

        assert_eq!(ll.len(), lr.len())
    }

    #[test]
    fn test_text_report() {
        let mut envelope: serde_json::Value = serde_json::from_str(&load_test("asan_stack_bof.json")).unwrap();
        let report: EnrichedTriageInfo = serde_json::from_value(
            envelope.get_mut("report").unwrap().take()
        ).unwrap();

        let envelope_s: ReportEnvelope = serde_json::from_value(envelope).unwrap();

        let text_golden: String = load_test("asan_stack_bof.txt");
        let text_new: String = format_text_report_new(build_text_report(&report, &envelope_s));

        println!("{}", text_new);
        // compare lines
        assert_lines_eq(&text_new, &text_golden);
    }
}
