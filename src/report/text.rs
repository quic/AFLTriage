// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//! AFLTriage's native "Text" report type.
use crate::{ReportOptions, ReportEnvelope};
use crate::debugger::gdb::*;
use crate::report::enriched::*;
use crate::util::{shell_join, elide_size};

use std::collections::HashSet;

enum TextReportSectionEntry {
    Line(String),
    Section(TextReportSection),
}

struct TextReportSection {
    section_name: String,
    entries: Vec<TextReportSectionEntry>,
}

impl TextReportSection {
    fn new(name: String) -> Self {
        TextReportSection {
            section_name: name,
            entries: vec![],
        }
    }

    #[allow(dead_code)]
    fn add(&mut self, entry: TextReportSectionEntry) {
        self.entries.push(entry);
    }

    fn add_line(&mut self, line: String) {
        self.entries.push(TextReportSectionEntry::Line(line));
    }

    fn add_section(&mut self, section: TextReportSection) {
        self.entries.push(TextReportSectionEntry::Section(section));
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

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

struct TextReportSections {
    header: TextReportSection,
    register_info: TextReportSection,
    crash_context: TextReportSection,
    backtrace: TextReportSection,
    sanitizer_report: TextReportSection,
    child_output: TextReportSection,
}

/// Render a text report using information from [EnrichedTriageInfo] and the corresponding
/// [ReportEnvelope].
pub fn format_text_report(einfo: &EnrichedTriageInfo, envelope: &ReportEnvelope) -> String {
    let sections = build_text_report(einfo, envelope);

    let mut report: String = String::new();

    let sec_order = vec![
        &sections.header,
        &sections.backtrace,
        &sections.sanitizer_report,
        &sections.crash_context,
        &sections.register_info,
        &sections.child_output,
    ];

    for sec in sec_order {
        if sec.len() > 0 {
            report += &sec.format().trim();
            report += "\n\n";
        }
    }

    // remove all but last newline
    report = report.trim().to_string();
    report += "\n";
    report
}

fn build_text_report(einfo: &EnrichedTriageInfo, envelope: &ReportEnvelope) -> TextReportSections {
    let mut header = TextReportSection::new("".into());
    let mut register_info = TextReportSection::new("Register info".into());
    let mut crash_context = TextReportSection::new("Crash context".into());

    let mut backtrace = TextReportSection::new("Crashing thread backtrace".into());
    let mut sanitizer_report = TextReportSection::new("Sanitizer Report".into());
    let mut child_output = TextReportSection::new("".into());

    header.add_line(format!(
        "Summary: {}\nCommand line: {}\nTestcase: {}\nCrash bucket: {}",
        einfo.summary, shell_join(&envelope.command_line), shlex::quote(&envelope.testcase), envelope.bucket.strategy_result,
    ));

    build_register_info(einfo, &mut register_info);
    build_instruction_context(einfo, &mut crash_context);
    build_backtrace(einfo, &mut backtrace);

    if let Some(reports) = &einfo.sanitizer_reports {
        // TODO: multiple reports
        if reports.len() > 0 {
            let san_report = &reports[0];
            if !san_report.body.is_empty() {
                // adjust the section title
                let san_name = san_report.name_prefer_short();
                sanitizer_report.section_name = format!("{} Report", san_name);
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
                    let lines = build_source_context(symbol, source_ctx);
                    ctx.extend(lines);
                }
            }

            if !file_sym.is_empty() {
                ctx.push(format!("at {}", file_sym));
            }
        }

        for line in &ctx {
            backtrace.add_line(format!("{:pad$}{}", "", line, pad = frame_pad));
        }

        if !ctx.is_empty() {
            backtrace.add_line(format!(""));
        }
    }
}

fn build_source_context(symbol: &GdbSymbol, source_ctx: &Vec<EnrichedSourceContext>) -> Vec<String> {
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
    let section_title = |name: &str, output: &str| -> String {
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

#[cfg(test)]
mod test {
    use super::*;
    use std::path::PathBuf;

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
        let text: String = format_text_report(&report, &envelope_s);

        assert_lines_eq(&text, &text_golden);
    }
}
