// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//! AFL specific handling
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Error};
use std::path::Path;
use std::str::FromStr;

/// See AFL's documentation for an explanation of these fields
#[derive(Debug, PartialEq)]
pub struct AflStats {
    pub start_time: u64,
    pub last_update: u64,
    pub run_time: Option<u64>, /// AFL++
    pub fuzzer_pid: u64,
    pub cycles_done: u64,
    pub cycles_wo_finds: Option<u64>, /// AFL++
    pub execs_done: u64,
    pub execs_per_sec: f32,
    pub execs_ps_last_min: Option<f32>, /// AFL++
    pub paths_total: u64,
    pub paths_favored: u64,
    pub paths_found: u64,
    pub paths_imported: u64,
    pub max_depth: u64,
    pub cur_path: u64,
    pub pending_favs: u64,
    pub pending_total: u64,
    pub variable_paths: u64,
    pub stability: f32,
    pub bitmap_cvg: f32,
    pub unique_crashes: u64,
    pub unique_hangs: u64,
    pub last_path: u64,
    pub last_crash: u64,
    pub last_hang: u64,
    pub execs_since_crash: u64,
    pub exec_timeout: u64,
    pub slowest_exec_ms: u64, /// Field order from here changes from AFL -> AFL++
    // This can be a string: https://github.com/google/AFL/blob/61037103ae3722c8060ff7082994836a794f978e/afl-fuzz.c#L3504
    pub peak_rss_mb: Option<u64>, /// Does not exist when AFL is running
    pub cpu_affinity: Option<i64>, /// AFL++
    pub edges_found: Option<u64>, /// AFL++
    pub var_byte_count: Option<u64>, /// AFL++
    pub havoc_expansion: Option<u64>, /// AFL++
    pub testcache_size: Option<u64>, /// AFL++
    pub testcache_count: Option<u64>, /// AFL++
    pub testcache_evict: Option<u64>, /// AFL++
    pub afl_banner: String,
    pub afl_version: String,
    pub target_mode: String,
    pub command_line: String,

}

/// Read and tokenize AFL status from the `fuzzer_stats` file present in AFL directories.
/// Use [validate_afl_fuzzer_stats] to convert tokenized strings into [AflStats].
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

#[allow(clippy::upper_case_acronyms)]
#[doc(hidden)]
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

/// Validate KV pairs parsed from AFL's `fuzzer_stats` and return [AflStats] on success
/// Some keys are required to always be present and others are wrapped in [Option].
pub fn validate_afl_fuzzer_stats<S: std::hash::BuildHasher>(
    kv: &HashMap<String, String, S>,
) -> Result<AflStats, String> {
    // Anything conversion with a ? is required
    Ok(AflStats {
        start_time: kv.to_num("start_time")?,
        last_update: kv.to_num("last_update")?,
        run_time: kv.to_num("run_time").ok(),
        fuzzer_pid: kv.to_num("fuzzer_pid")?,
        cycles_done: kv.to_num("cycles_done")?,
        cycles_wo_finds: kv.to_num("cycles_wo_finds").ok(),
        execs_done: kv.to_num("execs_done")?,
        execs_per_sec: kv.to_num("execs_per_sec")?,
        execs_ps_last_min: kv.to_num("execs_ps_last_min").ok(),
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
        slowest_exec_ms: kv.to_num("slowest_exec_ms")?,
        peak_rss_mb: kv.to_num("peak_rss_mb").ok(),
        cpu_affinity: kv.to_num("cpu_affinity").ok(),
        edges_found: kv.to_num("edges_found").ok(),
        var_byte_count: kv.to_num("var_byte_count").ok(),
        havoc_expansion: kv.to_num("havoc_expansion").ok(),
        testcache_size: kv.to_num("testcache_size").ok(),
        testcache_count: kv.to_num("testcache_count").ok(),
        testcache_evict: kv.to_num("testcache_evict").ok(),
        afl_banner: kv.to_str("afl_banner")?,
        afl_version: kv.to_str("afl_version")?,
        target_mode: kv.to_str("target_mode")?,
        command_line: kv.to_str("command_line")?,
    })

    // TODO: notify on unrecognized stats being parsed to allow for future versions
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use super::*;

    fn test_path(p: &str) -> PathBuf {
        let mut path = PathBuf::from(file!());
        path.pop();
        path.push("res");
        path.push("test_aflstats");
        path.push(p);
        path
    }

    #[test]
    fn test_afl_stats() {
        let s = parse_afl_fuzzer_stats(&test_path("afl_normal.txt"));
        assert!(s.is_ok());
        let s2 = validate_afl_fuzzer_stats(&s.unwrap());
        assert!(s2.is_ok());
        let s2v = s2.unwrap();
        assert!(s2v.peak_rss_mb.is_some());
        assert!(s2v.cycles_wo_finds.is_none());
        assert_eq!(s2v.fuzzer_pid, 30896);
        assert_eq!(s2v.stability, 99.58);
        assert_eq!(s2v.target_mode, "default");

        let s = parse_afl_fuzzer_stats(&test_path("afl_in_progress.txt"));
        assert!(s.is_ok());
        let s2 = validate_afl_fuzzer_stats(&s.unwrap());
        assert!(s2.is_ok());
        assert!(s2.unwrap().peak_rss_mb.is_none());

        let s = parse_afl_fuzzer_stats(&test_path("aflpp_normal.txt"));
        assert!(s.is_ok());
        let s2 = validate_afl_fuzzer_stats(&s.unwrap());
        assert!(s2.is_ok());
        let s2v = s2.unwrap();
        assert!(s2v.peak_rss_mb.is_some());
        assert!(s2v.cycles_wo_finds.is_some());
        assert_eq!(s2v.target_mode, "shmem_testcase default");
        assert_eq!(s2v.execs_ps_last_min.unwrap(), 0.0);
    }
}
