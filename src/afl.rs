// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Error};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug)]
pub struct AflStats {
    pub start_time: i64,
    pub last_update: i64,
    pub fuzzer_pid: i64,
    pub cycles_done: i64,
    pub execs_done: i64,
    pub execs_per_sec: f32,
    pub paths_total: i64,
    pub paths_favored: i64,
    pub paths_found: i64,
    pub paths_imported: i64,
    pub max_depth: i64,
    pub cur_path: i64,
    pub pending_favs: i64,
    pub pending_total: i64,
    pub variable_paths: i64,
    pub stability: f32,
    pub bitmap_cvg: f32,
    pub unique_crashes: i64,
    pub unique_hangs: i64,
    pub last_path: i64,
    pub last_crash: i64,
    pub last_hang: i64,
    pub execs_since_crash: i64,
    pub exec_timeout: i64,
    pub afl_banner: String,
    pub afl_version: String,
    pub target_mode: String,
    pub command_line: String,
    pub slowest_exec_ms: i64,
    pub peak_rss_mb: i64,
}

pub fn parse_afl_fuzzer_stats(filename: &Path) -> Result<HashMap<String, String>, Error> {
    let re = Regex::new(r"^([^: ]+)[ ]+: (.*)$").unwrap();
    let input = File::open(filename)?;
    let reader = BufReader::new(input);

    let mut kv = HashMap::new();

    for line in reader.lines() {
        let good_line = line?;

        if let Some(caps) = re.captures(&good_line) {
            kv.insert(
                caps.get(1).unwrap().as_str().to_string(),
                caps.get(2).unwrap().as_str().to_string(),
            );
        }
    }

    Ok(kv)
}

pub fn afl_list_testcases(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut testcases = fs::read_dir(path)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()?;

    testcases.sort();
    Ok(testcases)
}

#[allow(clippy::upper_case_acronyms)]
trait KVConverter {
    fn to_str(&self, key: &str) -> Result<String, String>;
    fn to_num<T: FromStr>(&self, key: &str) -> Result<T, String>;
    fn to_num_percent<T: FromStr>(&self, key: &str) -> Result<T, String>;
}

impl<S: std::hash::BuildHasher> KVConverter for HashMap<String, String, S> {
    fn to_str(&self, key: &str) -> Result<String, String> {
        match self.get(key) {
            Some(v) => Ok(v.to_string()),
            None => Err(format!("Missing key {}", key)),
        }
    }

    fn to_num<T: FromStr>(&self, key: &str) -> Result<T, String> {
        match self.to_str(key)?.parse::<T>() {
            Ok(res) => Ok(res),
            Err(_) => Err(format!(
                "Failed to convert {} to number ({})",
                key,
                std::any::type_name::<T>()
            )),
        }
    }

    fn to_num_percent<T: FromStr>(&self, key: &str) -> Result<T, String> {
        let value = self.to_str(key)?;
        let len = value.len();

        if len == 0 {
            return Err(format!("Invalid percentage key={} value={}", key, value));
        }

        match (&value[..len - 1]).parse::<T>() {
            Ok(res) => Ok(res),
            Err(_) => Err(format!(
                "Failed to convert {} to number ({})",
                key,
                std::any::type_name::<T>()
            )),
        }
    }
}

pub fn validate_afl_fuzzer_stats<S: std::hash::BuildHasher>(
    kv: &HashMap<String, String, S>,
) -> Result<AflStats, String> {
    Ok(AflStats {
        start_time: kv.to_num("start_time")?,
        last_update: kv.to_num("last_update")?,
        fuzzer_pid: kv.to_num("fuzzer_pid")?,
        cycles_done: kv.to_num("cycles_done")?,
        execs_done: kv.to_num("execs_done")?,
        execs_per_sec: kv.to_num("execs_per_sec")?,
        paths_total: kv.to_num("paths_total")?,
        paths_favored: kv.to_num("paths_favored")?,
        paths_found: kv.to_num("paths_found")?,
        paths_imported: kv.to_num("paths_imported")?,
        max_depth: kv.to_num("max_depth")?,
        cur_path: kv.to_num("cur_path")?,
        pending_favs: kv.to_num("pending_favs")?,
        pending_total: kv.to_num("pending_total")?,
        variable_paths: kv.to_num("variable_paths")?,
        stability: kv.to_num_percent("stability")?,
        bitmap_cvg: kv.to_num_percent("bitmap_cvg")?,
        unique_crashes: kv.to_num("unique_crashes")?,
        unique_hangs: kv.to_num("unique_hangs")?,
        last_path: kv.to_num("last_path")?,
        last_crash: kv.to_num("last_crash")?,
        last_hang: kv.to_num("last_hang")?,
        execs_since_crash: kv.to_num("execs_since_crash")?,
        exec_timeout: kv.to_num("exec_timeout")?,
        afl_banner: kv.to_str("afl_banner")?,
        afl_version: kv.to_str("afl_version")?,
        target_mode: kv.to_str("target_mode")?,
        command_line: kv.to_str("command_line")?,
        slowest_exec_ms: kv.to_num("slowest_exec_ms")?,
        peak_rss_mb: kv.to_num("peak_rss_mb")?,
    })

    // TODO: notify on unrecognized stats being parsed to allow for future versions
    // TODO: derive target command line from afl command line
}
