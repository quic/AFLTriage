// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use serde::{Deserialize, Serialize};
use regex::Regex;

lazy_static! {
    static ref R_ASAN_HEADLINE: Regex = Regex::new(
        r#"(?x)
        ([=]+[\r\n]+)?
        (?P<pid>=+[0-9]+=+)\s*ERROR:\s*AddressSanitizer:\s*
        (attempting\s)?(?P<reason>[-_A-Za-z0-9]+)[^\r\n]*[\r\n]+
        (?P<operation>[-_A-Za-z0-9]+)?
        "#
    )
    .unwrap();
    static ref R_ASAN_FRAME: Regex = Regex::new(r#"#(?P<num>[0-9]+)\s+(?P<addr>0x[a-fA-F0-9]+)"#).unwrap();
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SanitizerReport {
    pub sanitizer: String,
    pub stop_reason: String,
    pub operation: String,
    pub frames: Vec<u64>,
    pub body: String,
}

// TODO: support multiple sanitizer reports in successsion
pub fn sanitizer_report_extract(input: &str) -> Option<SanitizerReport> {
    // find the NEWEST sanitizer headline
    // regex doesn't support finding in reverse so we go at it forward
    let asan_match = R_ASAN_HEADLINE.captures_iter(input).last();

    // cut out the ASAN body from the child's output
    let asan_headline = asan_match?;
    let asan_start_marker = asan_headline.name("pid").unwrap().as_str();

    // find the bounds of the ASAN print to capture it raw
    let asan_raw_headline = asan_headline.get(0).unwrap();
    let asan_start_pos = asan_raw_headline.start();

    let asan_body_large = &input[asan_headline.name("pid").unwrap().start()..];
    let next_pos = asan_body_large.lines().take_while(|x| x.find(asan_start_marker).is_some()).map(|x| x.len()+1).sum::<usize>() + asan_headline.name("pid").unwrap().start();

    // This is not perfectly reliable. For instance, if ASAN_OPTIONS="halt_on_error=0"
    // then there will be no terminating ==1234==ABORTING token.
    // In that case the only safe option is to eat the rest of the string
    // Sanitizers really need machine readable output
    let end_pos: usize = if let Some(pos_rel) = &input[next_pos..].find(asan_start_marker) {
        let pos = pos_rel + next_pos;
        let skip_len = &input[pos..].find("\n").unwrap_or(0);
        pos + skip_len
    } else if let Some(pos_rel) = &input[next_pos..].find("SUMMARY: ") {
        let pos = pos_rel + next_pos;
        let skip_len = &input[pos..].find("\n").unwrap_or(0);
        pos + skip_len
    } else {
        // no match otherwise
        next_pos
    };

    let asan_body = &input[asan_start_pos..end_pos];

    let stop_reason = asan_headline.name("reason").unwrap().as_str().to_string();

    // Try and find the frame where ASAN was triggered from
    // That way we can print a better info message
    let mut asan_frames = Vec::new();

    for (i, frame) in R_ASAN_FRAME.captures_iter(asan_body).enumerate() {
        let id = u64::from_str_radix(&(frame.name("num").unwrap().as_str()), 10).unwrap();
        let addr = u64::from_str_radix(&(frame.name("addr").unwrap().as_str())[2..], 16).unwrap();

        if (i as u64) != id {
            break
        }

        asan_frames.push(addr);
    }

    let operation: &str = match asan_headline.name("operation") {
        Some(op) => {
            if stop_reason == "SEGV" {
                ""
            } else {
                op.as_str()
            }
        }
        _ => "",
    };

    Some(SanitizerReport {
        sanitizer: "AddressSanitizer".into(), // TODO: support more sanitizers
        stop_reason,
        operation: operation.to_string(),
        frames: asan_frames,
        body: asan_body.trim_end().to_string(),
    })
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
        path.push("test_sanitizer_reports");
        path.push(p);
        path
    }

    #[test]
    fn test_asan_report_parsing() {
        let a = load_test("asan_fpe.txt");
        let r = sanitizer_report_extract(&a).unwrap();

        assert_eq!(r.stop_reason, "FPE");
        assert_eq!(r.operation, "");
        assert_eq!(r.frames[0], 0x560b425587af);

        let a = load_test("asan_segv.txt");
        let r = sanitizer_report_extract(&a).unwrap();

        assert_eq!(r.stop_reason, "SEGV");
        assert_eq!(r.operation, "");
        assert_eq!(r.frames[0], 0x561010d1d83b);

        let a = load_test("asan_oob_read.txt");
        let r = sanitizer_report_extract(&a).unwrap();

        assert_eq!(r.stop_reason, "stack-buffer-overflow");
        assert_eq!(r.operation, "READ");
        assert_eq!(r.frames[0], 0x5561e001bba8);
        assert_eq!(r.body, a.trim());

        let a = load_test("asan_multi.txt");
        let r = sanitizer_report_extract(&a).unwrap();

        assert_eq!(r.stop_reason, "SEGV");
        assert_eq!(r.operation, "");
        assert_eq!(r.frames[0], 0x561010d1d83b);
        assert!(r.body.ends_with("==32232==ABORTING"));

        let a = load_test("asan_no_end.txt");
        let r = sanitizer_report_extract(&a).unwrap();

        assert_eq!(r.stop_reason, "SEGV");
        assert_eq!(r.operation, "");
        assert_eq!(r.frames[0], 0x561010d1d83b);
        assert!(r.body.ends_with("SUMMARY: AddressSanitizer: SEGV /tmp/test.c:14 in crash_segv"));

        let a = load_test("asan_trunc.txt");
        let r = sanitizer_report_extract(&a).unwrap();

        assert_eq!(r.stop_reason, "SEGV");
        assert_eq!(r.operation, "");
        assert!(r.frames.is_empty()); // unable to get frames on truncated reports
        assert!(r.body.ends_with("access."));

        let a = load_test("asan_interceptor_gcc.txt");
        let r = sanitizer_report_extract(&a).unwrap();

        assert_eq!(r.stop_reason, "global-buffer-overflow");
        assert_eq!(r.operation, "READ");
        assert_eq!(r.frames.len(), 9);
        assert_eq!(r.frames[0], 0x7f91702c0074);
        assert_eq!(r.frames[1], 0x7f917033554f);
        assert_eq!(r.frames[8], 0x561eefdccbd9);

        let a = load_test("asan_interceptor.txt");
        let r = sanitizer_report_extract(&a).unwrap();

        assert_eq!(r.stop_reason, "global-buffer-overflow");
        assert_eq!(r.operation, "READ");
        assert_eq!(r.frames.len(), 6);
        assert_eq!(r.frames[0], 0x43962a);
        assert_eq!(r.frames[5], 0x41ad89);

        assert!(sanitizer_report_extract("").is_none());

        let m = "==1==ERROR: AddressSanitizer: CODE\n";
        assert_eq!(sanitizer_report_extract("==1==ERROR: AddressSanitizer: CODE\n").unwrap(),
            SanitizerReport {
                sanitizer:  "AddressSanitizer".into(),
                stop_reason: "CODE".into(),
                operation: "".into(),
                frames: vec![],
                body: m.trim().into(),
            });
    }
}
