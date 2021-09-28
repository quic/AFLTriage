// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use serde::{Deserialize, Serialize};
use super::report::enriched::EnrichedTriageInfo;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct CrashBucketInfo {
    /// What is the stringified output from the bucketing function
    pub strategy_result: String,
    /// What hashing or other function was used to identify a crash
    pub strategy: CrashBucketStrategy,
    /// What stringified inputs were used as input to the bucketing function
    pub inputs: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum CrashBucketStrategy {
    afltriage,
    //first_frame,
    //first_n_frames(usize),
    //exploitable_major,
    //user,
}

pub fn bucket_crash(strategy: CrashBucketStrategy, einfo: &EnrichedTriageInfo) -> CrashBucketInfo {
    //let mut inputs = vec![];
    //let strategy_result = "".into();
    let (strategy_result, inputs) = match &strategy {
        afltriage => bucket_afltriage(einfo),
    };

    CrashBucketInfo {
        strategy_result,
        strategy,
        inputs,
    }
}

fn bucket_afltriage(einfo: &EnrichedTriageInfo) -> (String, Vec<String>) {
    let mut hash = md5::Context::new();
    let mut inputs = vec![];

    for fr in &einfo.faulting_thread.frames {
        let file_sym = match &fr.symbol {
            Some(symbol) => symbol.format_file(),
            None => "".to_string(),
        };

        // if we have a file symbol with a line, use it for hashing
        if !file_sym.is_empty() && file_sym.contains(':') {
            inputs.push(file_sym);
        } else if fr.module != "[stack]" && fr.module != "[heap]" {
            // don't consider the stack or heap for hashing
            inputs.push(fr.module_address.to_string());
        }
    }

    for i in &inputs {
        hash.consume(i.as_bytes());
    }

    (format!("{:x}", hash.compute()), inputs)
}
