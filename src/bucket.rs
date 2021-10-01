// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use serde::{Deserialize, Serialize};
use super::report::enriched::EnrichedTriageInfo;
use clap::arg_enum;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct CrashBucketInfo {
    /// What is the stringified output from the bucketing function
    pub strategy_result: String,
    /// What hashing or other function was used to identify a crash
    pub strategy: CrashBucketStrategy,
    /// What stringified inputs were used as input to the bucketing function
    pub inputs: Vec<String>,
}

arg_enum! {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[allow(non_camel_case_types)]
    pub enum CrashBucketStrategy {
        none,
        afltriage,
        first_frame,
        first_frame_raw,
        first_5_frames,
        function_names,
        first_function_name,
        //exploitable_major,
        //user,
    }
}

pub fn bucket_crash(strategy: CrashBucketStrategy, einfo: &EnrichedTriageInfo) -> CrashBucketInfo {
    let max_frames = einfo.faulting_thread.frames.len();
    let (strategy_result, inputs) = match &strategy {
        CrashBucketStrategy::none => ("".into(), vec![]),
        CrashBucketStrategy::afltriage => bucket_first_n_frames(einfo, max_frames),
        CrashBucketStrategy::first_frame => bucket_first_n_frames(einfo, 1),
        CrashBucketStrategy::first_frame_raw => bucket_first_n_frames_raw(einfo, 1),
        CrashBucketStrategy::function_names => bucket_n_function_names(einfo, max_frames),
        CrashBucketStrategy::first_function_name => bucket_n_function_names(einfo, 1),
        CrashBucketStrategy::first_5_frames => bucket_first_n_frames(einfo, 5),
    };

    CrashBucketInfo {
        strategy_result,
        strategy,
        inputs,
    }
}

fn bucket_first_n_frames(einfo: &EnrichedTriageInfo, n: usize) -> (String, Vec<String>) {
    let mut hash = md5::Context::new();
    let mut inputs = get_frame_signatures(einfo);

    inputs = inputs[..std::cmp::min(n, inputs.len())].to_vec();

    for i in &inputs {
        hash.consume(i.as_bytes());
    }

    (format!("{:x}", hash.compute()), inputs)
}

fn bucket_n_function_names(einfo: &EnrichedTriageInfo, n: usize) -> (String, Vec<String>) {
    let mut hash = md5::Context::new();
    let mut inputs = vec![];

    for fr in &einfo.faulting_thread.frames[einfo.faulting_frame_idx..] {
        inputs.push(
            fr.symbol
            .as_ref()
            .map(|x| x.function_name
                .as_ref()
                .map(|f| f.to_string())
            )
            .flatten()
            .unwrap_or(fr.module_address.to_string())
        );
    }

    inputs = inputs[..std::cmp::min(n, inputs.len())].to_vec();

    for i in &inputs {
        hash.consume(i.as_bytes());
    }

    (format!("{:x}", hash.compute()), inputs)
}

fn bucket_first_n_frames_raw(einfo: &EnrichedTriageInfo, n: usize) -> (String, Vec<String>) {
    let mut hash = md5::Context::new();
    let mut inputs = get_raw_frame_signatures(einfo);

    inputs = inputs[..std::cmp::min(n, inputs.len())].to_vec();

    for i in &inputs {
        hash.consume(i.as_bytes());
    }

    (format!("{:x}", hash.compute()), inputs)
}

fn get_frame_signatures(einfo: &EnrichedTriageInfo) -> Vec<String> {
    let mut inputs = vec![];

    for fr in &einfo.faulting_thread.frames[einfo.faulting_frame_idx..] {
        let file_sym = match &fr.symbol {
            Some(symbol) => symbol.format_file(),
            None => "".to_string(),
        };

        // if we have a file symbol with a line, use it for hashing
        if !file_sym.is_empty() && file_sym.contains(':') {
            inputs.push(file_sym);
        } else if fr.module != "[stack]" && fr.module != "[heap]" && fr.module != "??" {
            // don't consider the stack or heap for hashing
            // if we don't have a module, then also ignore
            // fall back to addresses
            inputs.push(fr.module_address.to_string());
        }
    }

    // I'm sure there is a better way of handling this situation
    if inputs.is_empty() {
        if einfo.faulting_thread.frames.is_empty() {
            inputs.push("UNKNOWN".to_string());
        } else {
            inputs.push(einfo.faulting_thread.frames[0].address.f.to_string());
        }
    }

    inputs
}

fn get_raw_frame_signatures(einfo: &EnrichedTriageInfo) -> Vec<String> {
    let mut inputs = vec![];

    for fr in &einfo.faulting_thread.frames {
        inputs.push(fr.address.f.to_string());
    }

    if einfo.faulting_thread.frames.is_empty() {
        inputs.push("UNKNOWN".to_string());
    }

    inputs
}
