// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use regex::Regex;

lazy_static! {
    static ref ALLOWED_CHARS: Regex = Regex::new(r#"[^A-Za-z0-9_-]"#).unwrap();
}

pub fn elide_size(s: &str, size: usize) -> String {
    if size < 3 {
        return "...".to_string();
    }

    let new_size = size - 3;

    if s.len() > new_size {
        format!("{}...", &s[..new_size])
    } else {
        s.to_string()
    }
}

pub fn tail_string(chars: &str, limit: usize) -> Vec<&str> {
    let mut lines: Vec<&str> = chars.rsplit('\n').take(limit).collect::<Vec<&str>>();

    lines.reverse();

    lines
}

pub fn sanitize(name: &str) -> String {
    let mut s = ALLOWED_CHARS.replace_all(name, "_").to_string();
    // TODO: sanitize entire string
    s.truncate(100);
    s
}
