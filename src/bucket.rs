// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//! Built-in methods to cluster crashes during the triage process.
//!
//! This clustering, also known as crash deduplication or crash bucketing, can help save time
//! triaging crash reports (as there will be less reports).  There are many tools that offer some
//! form of crash deduplication, such as Exploitable, Honggfuzz, CERT BFF, and more. Each has their
//! own techniques (or strategies) they employ, many of which are based around stack hashing.
//! AFLTriage draws upon previous work and builds in some simple strategies out of the box.
//!
//! ## Strategies
//! * [CrashBucketStrategy::none] - Do not use crash bucketing at all. Treat all crashes as new
//! findings.
//! * [CrashBucketStrategy::afltriage] - An opinionated strategy that uses either symbol
//! (file:line) or address information starting at the "first interesting frame" as bucket inputs.
//! * [CrashBucketStrategy::first_frame] - The same as `afltriage` but only consider the first
//! interesting frame.
//! * [CrashBucketStrategy::first_frame_raw] - Only use the address of the first raw (non-heuristicly determined) frame
//! * [CrashBucketStrategy::first_5_frames] - The same as `afltriage` but only consider the first
//! five interesting frames.
//! * [CrashBucketStrategy::function_names] - Only use the function names without offsets (or addresses if not
//! available)
//! * [CrashBucketStrategy::first_function_name] - The same as `function_names` but only the first
//! frame's function name
//!
//! Accurate crash bucketing is an active research area and is usually somewhat target specific. Many strategies are a heuristic at best.
//! This could lead to you missing truly unique crashes (false negative) or having many duplicate
//! crashes (false positive).
use serde::{Deserialize, Serialize};
use super::report::enriched::EnrichedTriageInfo;
use clap::arg_enum;

/// Information on the crash bucketing strategy, inputs, and output
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
    /// The built-in crash deduplication (crash bucketing) method (strategy) to use
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

/// Using [EnrichedTriageInfo] and a [CrashBucketStrategy], determine a unique string output that
/// attempts to captures the uniqueness of a crash.
pub fn bucket_crash(strategy: CrashBucketStrategy, einfo: &EnrichedTriageInfo) -> CrashBucketInfo {
    let max_frames = einfo.faulting_thread.frames.len();
    let (strategy_result, inputs) = match &strategy {
        CrashBucketStrategy::none => ("".into(), vec![]),
        CrashBucketStrategy::afltriage => bucket_n_frames(einfo, max_frames),
        CrashBucketStrategy::first_frame => bucket_n_frames(einfo, 1),
        CrashBucketStrategy::first_frame_raw => bucket_n_frames_raw(einfo, 1),
        CrashBucketStrategy::function_names => bucket_n_function_names(einfo, max_frames),
        CrashBucketStrategy::first_function_name => bucket_n_function_names(einfo, 1),
        CrashBucketStrategy::first_5_frames => bucket_n_frames(einfo, 5),
    };

    CrashBucketInfo {
        strategy_result,
        strategy,
        inputs,
    }
}

/// Bucket the first guessed `n` frames
fn bucket_n_frames(einfo: &EnrichedTriageInfo, n: usize) -> (String, Vec<String>) {
    let mut hash = md5::Context::new();
    let mut inputs = get_frame_signatures(einfo);

    inputs = inputs[..std::cmp::min(n, inputs.len())].to_vec();

    for i in &inputs {
        hash.consume(i.as_bytes());
    }

    (format!("{:x}", hash.compute()), inputs)
}

/// Bucket using the first `n` function names
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

/// Bucket the first true `n` frames
fn bucket_n_frames_raw(einfo: &EnrichedTriageInfo, n: usize) -> (String, Vec<String>) {
    let mut hash = md5::Context::new();
    let mut inputs = get_raw_frame_signatures(einfo);

    inputs = inputs[..std::cmp::min(n, inputs.len())].to_vec();

    for i in &inputs {
        hash.consume(i.as_bytes());
    }

    (format!("{:x}", hash.compute()), inputs)
}

/// Get frame signatures (file:line, module+offset, or address) starting from the guessed faulting
/// frame, or if not available, the first true frame
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

/// Get the "raw" frame signatures, which is just their address in string form
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
