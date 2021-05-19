// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use regex::Regex;

lazy_static! {
    static ref ALLOWED_CHARS: Regex = Regex::new(r#"[^A-Za-z0-9_-]"#).unwrap();
}

pub struct UniqueIdFactory {
    identifiers: HashSet<String>
}

pub fn elide_size(s: &str, size: usize) -> String {
    if size < 3 {
        return format!("...")
    }

    let new_size = size - 3;

    if s.len() > new_size {
        return format!("{}...", &s[..new_size])
    } else {
        return s.to_string()
    }
}

pub fn tail_string<'a>(chars: &'a str, limit: usize) -> Vec<&'a str> {
    let mut lines: Vec<&str> = chars
        .rsplit("\n")
        .take(limit)
        .collect::<Vec<&str>>();

    lines.reverse();

    lines
}

pub fn sanitize(name: &str) -> String {
    let mut s = ALLOWED_CHARS.replace_all(name, "_").to_string();
    // TODO: sanitize entire string 
    s.truncate(100);
    return s
}

impl UniqueIdFactory {
    pub fn new() -> UniqueIdFactory {
        UniqueIdFactory { identifiers: HashSet::new() }
    }

    pub fn from_path(&mut self, path: &Path) -> String {
        let filename = match path.file_name() {
            Some(name) => sanitize(&name.to_string_lossy().to_string()),
            None => "".to_string()
        };

        if filename == "" {
            let mut num = 0;

            loop {
                let candidate = format!("NO_NAME_{}", num);

                if !self.identifiers.contains(&candidate) {
                    self.identifiers.insert(candidate.to_string());
                    return candidate;
                }

                num += 1;
            }
        }

        if !self.identifiers.contains(&filename) {
            self.identifiers.insert(filename.to_string());
            return filename;
        }

        let parent = match path.parent() {
            Some(parent) => {
                match parent.file_name() {
                    Some(name) => sanitize(&name.to_string_lossy().to_string()),
                    None => "".to_string()
                }
            }
            None => "".to_string()
        };

        let more_specific: String = match parent.is_empty() {
            true => filename,
            false => format!("{}_{}", parent, filename)
        };

        if !self.identifiers.contains(&more_specific) {
            self.identifiers.insert(more_specific.to_string());
            return more_specific;
        }

        // fallback to just name and number
        let mut num = 0;

        loop {
            let candidate = format!("{}_{}", more_specific, num);

            if !self.identifiers.contains(&candidate) {
                self.identifiers.insert(candidate.to_string());
                return candidate;
            }

            num += 1;
        }
    }

}
