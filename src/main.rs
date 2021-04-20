// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use clap::{arg_enum, Arg, ArgMatches, App, AppSettings, SubCommand, crate_version};
use std::path::{Path, PathBuf};
use is_executable::IsExecutable;
use std::process::{Command, Output};
use std::io::{self, Write, BufRead};
use std::collections::HashSet;
use std::cmp;
use which::which;
use md5;
use libc;
use indicatif::{ProgressBar, ProgressStyle, ProgressIterator, ParallelProgressIterator};
use rayon::prelude::*;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate clap;

pub mod afl;
pub mod util;
pub mod process;
pub mod gdb_triage;

use gdb_triage::GdbTriager;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

// strict/fuzzy stack hash

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum OutputFormat {
        text,
        markdown,
        json
    }
}

fn isatty() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
}

fn setup_command_line() -> ArgMatches<'static> {
    let mut app = App::new("afltriage")
                          .version(crate_version!())
                          .about("Quickly triage and summarize crashing testcases")
                          .setting(AppSettings::TrailingVarArg)
                          .setting(AppSettings::DontDelimitTrailingValues)
                          .arg(Arg::with_name("input")
                               .short("-i")
                               .long("--input")
                               .takes_value(true)
                               .required(true)
                               .multiple(true)
                               .help("A path to a single testcase, directory of testcases, AFL directory, and/or directory of AFL directories to be triaged."))
                          .arg(Arg::with_name("recursive")
                               .short("-R")
                               .long("--recursive")
                               .help("Recursively process testcases from input directory."))
                          .arg(Arg::with_name("dryrun")
                               .long("--dry-run")
                               .takes_value(false)
                               .help("Perform sanity checks and describe the inputs to be triaged."))
                          .arg(Arg::with_name("watch")
                               .short("-w")
                               .long("--watch")
                               .help("Monitor input paths for newly created testcases."))
                          .arg(Arg::with_name("output")
                               .short("-o")
                               .long("--output")
                               .takes_value(true)
                               .required(true)
                               .help("The output path for triage report files. Use '-' to print to console."))
                          .arg(Arg::with_name("ofmt")
                               .long("--output-format")
                               .takes_value(true)
                               .possible_values(&OutputFormat::variants())
                               .default_value("text")
                               .case_insensitive(true)
                               .help("The triage report output format."))
                          .arg(Arg::with_name("triage_cmd")
                               .value_name("triage_cmd")
                               .takes_value(true)
                               .required(true)
                               .multiple(true)
                               .index(1)
                               .help("The binary executable and args to execute. Use '@@' as a placeholder for the path to the input file."));

    return app.get_matches();
}

struct CrashReport {
    headline: String,
    backtrace: String,
    stackhash: String
}

struct TriageState<'a> {
    testcase: &'a str,
    report: CrashReport
}

fn process_test_case(gdb: &GdbTriager, binary_args: &Vec<&str>, testcase: &str) -> CrashReport {
    let mut prog_args: Vec<String> = Vec::new();

    for arg in binary_args.iter() {
        if arg.to_string() == "@@" {
            prog_args.push(testcase.to_string());
        } else {
            prog_args.push(arg.to_string());
        }
    }

    let res = match gdb.triage_testcase(prog_args) {
        Ok(res) => res,
        Err(e) => {
            let headline = format!("Failed to triage: {}", e);
            return CrashReport{headline, backtrace:"".to_string(), stackhash:"".to_string()};
        },
    };

    if res.current_tid == -1 {
        let headline = format!("No crash");
        return CrashReport{headline, backtrace:"".to_string(), stackhash:"".to_string()};
    } else {
        for thread in res.threads {
            if thread.tid == res.current_tid {
                let frame_names = thread.backtrace.iter()
                    .map(|e| e.symbol.function_name.as_str())
                    .collect::<Vec<&str>>();
                let frame = thread.backtrace.get(0).unwrap();
                /*let msg = format!("CRASH: tid {} {} [input {}]",
                         res.current_tid, frame.symbol.function_name, testcase);*/
                //let last_frame_idx = cmp::min(10, frame_names.len());
                //let frames = &frame_names[7..last_frame_idx];
                //let frames = &frame_names[7..last_frame_idx];
                let frames = &thread.backtrace[7..];
                let headline = format!("CRASH: tid {} in {}",
                         res.current_tid, frames.get(0).unwrap().symbol.function_name.as_str());

                let mut major_hash = md5::Context::new();
                let mut backtrace = String::new();

                for (i, fr) in frames.iter().enumerate() {
                    major_hash.consume(fr.pretty_address.as_bytes());
                    backtrace += &format!("#{:<2} pc {:<08x} {} ({})\n",
                        i, fr.address, fr.module, fr.symbol.function_name);
                }

                return CrashReport{headline, backtrace,
                stackhash: String::from(format!("{:x}", major_hash.compute()))};
            }
        }

        return CrashReport{headline:"Thread not found".to_string(), backtrace:"".to_string(), stackhash:"".to_string()};
    }
}

enum UserInputPathType {
    Unknown,
    Missing,
    Single,
    PlainDir,
    AflDir
}

struct UserInputPath {
    ty: UserInputPathType,
    path: PathBuf,
    fuzzer_stats: Option<afl::AflStats>
}

struct Testcase {
    path: PathBuf,
    /// Must be safe for filesystem
    unique_id: String
}

fn determine_input_type(input: &PathBuf) -> UserInputPathType {
    let metadata = match input.symlink_metadata() {
        Ok(meta) => meta,
        Err(e) => return UserInputPathType::Missing
    };

    if metadata.file_type().is_file() {
        return UserInputPathType::Single;
    }

    // looks like an AFL dir
    if input.join("fuzzer_stats").exists() ||
       input.join("queue").exists() ||
       input.join("crashes").exists() {
        return UserInputPathType::AflDir;
    }

    if metadata.file_type().is_dir() {
        return UserInputPathType::PlainDir;
    }

    return UserInputPathType::Unknown;
}

fn sanity_check(gdb: &GdbTriager, binary_args: &Vec<&str>) -> bool {
    match binary_args.iter().find(|s| s.to_string() == "@@") {
        None => {
            println!("[!] Image triage args missing file placeholder: @@");
            return false
        }
        _ => ()
    }

    let rawexe = binary_args.get(0).unwrap();
    let exe = PathBuf::from(rawexe);
    let justfilename = exe.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap();

    // A PATH resolvable name
    if justfilename == rawexe.to_string() {
        match which::which(rawexe) {
            Err(e) => {
                println!("[X] Binary {} not found in PATH. Try using the absolute path",
                         rawexe);
                return false
            }
            _ => ()
        }

        println!("PATH based name");
    } else {
        if !exe.is_executable() {
            println!("[X] Binary {} does not exist or is not executable", rawexe);
            return false;
        }
    }

    if !gdb.has_supported_gdb() {
        return false
    }

    true
}

fn main() {
    /* AFLTriage Flow
     *
     * 1. Environment sanity check: gdb python, binary exists
     * 2. Input processing: for each input path determine single file, dir with files, afl dir single, afl
     *    dir primary/secondaries
     *      - Reject AFL dirs for multiple different fuzzers and provide guidance for this
     * 3. Input collection: resolve all paths to input files in a stable order
     *      - Convert paths to unique identifiers for report writing
     * 4. Triaging: collect crash info, process crash info, classify/dedup
     *      - Write report in text/json
     */

    let args = setup_command_line();

    println!("AFLTriage v{}\n", VERSION);

    let binary_args: Vec<&str> = args.values_of("triage_cmd").unwrap().collect();

    // TODO: fix binary_args validation
    let gdb: GdbTriager = gdb_triage::GdbTriager::new();

    if !sanity_check(&gdb, &binary_args) {
        return
    }

    println!("[+] Image triage cmdline: \"{}\"", binary_args.join(" "));

    let input_paths: Vec<&str> = args.values_of("input").unwrap().collect();

    let mut processed_inputs = Vec::new();

    for input in input_paths {
        let path = PathBuf::from(input);
        let ty = determine_input_type(&path);

        processed_inputs.push(UserInputPath {
            ty, path, fuzzer_stats: None
        });
    }

    let mut all_testcases = Vec::new();
    let mut ids = util::UniqueIdFactory::new();

    for mut input in processed_inputs {
        let pathStr = input.path.to_str().unwrap();

        match input.ty {
            UserInputPathType::Single => {
                println!("[+] Triaging single {}", pathStr);
                all_testcases.push(Testcase {
                    unique_id: ids.from_path(&input.path.as_path()),
                    path: input.path
                });
            },
            UserInputPathType::PlainDir => {
                match afl::afl_list_testcases(input.path.as_path()) {
                    Ok(tcs) => {
                        let mut valid = 0;
                        for tc in tcs {
                            if tc.is_file() {
                                valid += 1;
                                all_testcases.push(Testcase {
                                    unique_id: ids.from_path(&tc),
                                    path: tc
                                });
                            }
                        }

                        if valid > 0 {
                            println!("[+] Triaging plain directory {} ({} files)",
                                pathStr, valid);
                        } else {
                            println!("[!] No files found in directory {}",
                                pathStr);
                        }
                    }
                    _ => println!("[!] Failed to get files from directory {}", pathStr)
                }
            },
            UserInputPathType::AflDir => {
                match afl::afl_list_testcases(input.path.join("crashes").as_path()) {
                    Ok(tcs) => {
                        let mut valid = 0;
                        for tc in tcs {
                            if tc.is_file() {
                                valid += 1;
                                all_testcases.push(Testcase {
                                    unique_id: ids.from_path(&tc),
                                    path: tc
                                });
                            }
                        }

                        // TODO: ignore README.txt
                        // TODO: filter command (.*id:.*)
                        if valid > 0 {
                            println!("[+] Triaging AFL directory {} ({} files)",
                                pathStr, valid);
                        } else {
                            println!("[!] No crashes found in AFL directory {}", pathStr);
                        }
                    }
                    Err(e) => println!("[!] Failed to get AFL crashes from directory {}: {}",
                                       pathStr, e)
                }

                let fuzzer_stats = match afl::parse_afl_fuzzer_stats(input.path.join("fuzzer_stats").as_path()) {
                    Ok(s) => {
                        match afl::validate_afl_fuzzer_stats(s) {
                            Ok(s2) => {
                                println!(" ├─ AFL Banner: {}", s2.afl_banner);
                                println!(" └─ AFL Version: {}", s2.afl_version);
                                Some(s2)
                            }
                            Err(e) => {
                                println!("[!] Failed to validate AFL fuzzer_stats: {}", e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        println!("[!] AFL directory is missing fuzzer_stats: {}", e);
                        None
                    }
                };

                input.fuzzer_stats = fuzzer_stats;
            },
            _ => println!("[!] Skipping unknown or missing path {}", pathStr),
        }
    }

    if all_testcases.len() == 0 {
        println!("No testcases found!");
        return
    }

    if args.is_present("dryrun") {
        println!("Exiting due to dry run");
        return
    }

    let requested_job_count = 20;
    let job_count = std::cmp::min(requested_job_count, all_testcases.len());

    // TODO: -n flag for parallelism
    rayon::ThreadPoolBuilder::new().num_threads(job_count).build_global().unwrap();

    let pb = ProgressBar::new((&all_testcases).len() as u64);
    let spinner_style = ProgressStyle::default_spinner()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
        .template("{prefix:.bold.dim} {spinner} {wide_msg}");

    let display_progress = isatty();
    if display_progress {
        pb.set_style(ProgressStyle::default_bar()
                     .template("{spinner:.green} [{pos}/{len} {elapsed_precise}] [{bar:.cyan/blue}] {msg}")
                     .progress_chars("#>-"));
        pb.enable_steady_tick(200);

        pb.set_message(format!("Processing initial {} test cases", job_count).as_str());
    } else {
        println!("{}", format!("Processing initial {} test cases", job_count).as_str());
    }

    let results : Vec<TriageState> = all_testcases.par_iter().map(|testcase| {
        let path = testcase.path.to_str().unwrap();
        let report = process_test_case(&gdb, &binary_args, path);

        if display_progress {
            pb.set_message(&report.headline);
            pb.inc(1);
        } else {
            println!("{}", report.headline);
        }

        return TriageState { testcase:path, report }
    }).collect::<Vec<TriageState>>();

    let mut seen = HashSet::new();

    // TODO: print triage stats (crash, no crash, error)
    for state in results {
        let hash = &state.report.stackhash;

        if hash == "" {
            continue
        }

        if !seen.contains(hash) {
            println!("--- --- --- --- --- ---\nTestcase: {}\nStack hash: {}\n\n\n{}\n\nbacktrace:\n{}\n",
                     state.testcase, state.report.stackhash, state.report.headline, state.report.backtrace);
            seen.insert(hash.to_string());
        }
    }
}
