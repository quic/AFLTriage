// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use regex::Regex;

lazy_static! {
    static ref ALLOWED_CHARS: Regex = Regex::new(r#"[^A-Za-z0-9_]"#).unwrap();
}

pub struct UniqueIdFactory {
    identifiers: HashSet<String>
}

impl UniqueIdFactory {
    pub fn new() -> UniqueIdFactory {
        UniqueIdFactory { identifiers: HashSet::new() }
    }

    fn sanitize(&self, name: String) -> String {
        let mut s = ALLOWED_CHARS.replace_all(&name, "_").to_string();
        // TODO: sanitize entire string 
        s.truncate(200);
        return s
    }

    pub fn from_path(&mut self, path: &Path) -> String {
        let filename = match path.file_name() {
            Some(name) => self.sanitize(name.to_string_lossy().to_string()),
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
                    Some(name) => self.sanitize(name.to_string_lossy().to_string()),
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
