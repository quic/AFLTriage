// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use clap::{arg_enum, Arg, ArgMatches, App, AppSettings, crate_version};
use std::path::PathBuf;
use is_executable::IsExecutable;
use std::collections::{HashSet, HashMap};
use std::cmp;
use which::which;
use std::env;
use regex::Regex;
use std::sync::{Arc, Mutex};
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
pub mod report;

use gdb_triage::{GdbTriager, GdbTriageResult};
use process::ChildResult;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

arg_enum! {
    #[derive(PartialEq, Debug)]

    // these are user facing
    #[allow(non_camel_case_types)]
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
    let app = App::new("afltriage")
                          .version(crate_version!())
                          .about("Quickly triage and summarize crashing testcases")
                          .usage("afltriage -i <input>... -o <output> <command>...")
                          .setting(AppSettings::TrailingVarArg)
                          .setting(AppSettings::DontDelimitTrailingValues)
                          .setting(AppSettings::DontCollapseArgsInUsage)
                          .arg(Arg::with_name("input")
                               .short("-i")
                               .takes_value(true)
                               .required(true)
                               .multiple(true)
                               .help("A path to a single testcase, directory of testcases, AFL directory, and/or directory of AFL directories to be triaged."))
                          .arg(Arg::with_name("dryrun")
                               .long("--dry-run")
                               .takes_value(false)
                               .help("Perform sanity checks and describe the inputs to be triaged."))
                          .arg(Arg::with_name("output")
                               .short("-o")
                               .takes_value(true)
                               .required(true)
                               .help("The output path for triage report files. Use '-' to print to console."))
                          .arg(Arg::with_name("debug")
                               .long("--debug")
                               .help("Enable low-level debugging of triage operations."))
                          .arg(Arg::with_name("child_output")
                               .long("--child-output")
                               .help("Include child output in triage reports."))
                          .arg(Arg::with_name("ofmt")
                               .long("--output-format")
                               .takes_value(true)
                               .possible_values(&OutputFormat::variants())
                               .default_value("text")
                               .required(false)
                               .case_insensitive(true)
                               .help("The triage report output format."))
                          .arg(Arg::with_name("command")
                               .multiple(true)
                               .required(true)
                               .help("The binary executable and args to execute. Use '@@' as a placeholder for the path to the input file."));

    return app.get_matches();
}

struct TestcaseResult<'a> {
    testcase: &'a str,
    result: TriageResult,
    report: Option<report::CrashReport>
}

struct TriageState {
    crashed: usize,
    no_crash: usize,
    errored: usize,
    crash_signature: HashSet<String>,
    unique_errors: HashMap<String, usize>,
}

enum TriageResult {
    NoCrash(ChildResult),
    Crash(GdbTriageResult),
    Error(String)
}

fn process_test_case(gdb: &GdbTriager, binary_args: &Vec<&str>, testcase: &str, debug: bool) -> TriageResult {
    let mut prog_args: Vec<String> = Vec::new();

    for arg in binary_args.iter() {
        if arg.to_string() == "@@" {
            prog_args.push(testcase.to_string());
        } else {
            prog_args.push(arg.to_string());
        }
    }

    let triage_result = match gdb.triage_testcase(prog_args, debug) {
        Ok(triage_result) => triage_result,
        Err(e) => {
            return TriageResult::Error(format!("Failed to triage: {}", e));
        },
    };

    let crashing_tid = triage_result.thread_info.current_tid;

    if crashing_tid == -1 {
        return TriageResult::NoCrash(triage_result.child);
    } else {
        let mut found = false;
        for thread in &triage_result.thread_info.threads {
            if thread.tid == crashing_tid {
                found = true;
                break
            }
        }

        if !found {
            return TriageResult::Error("Crashing thread not found in backtrace".into());
        } else {
            return TriageResult::Crash(triage_result);
        }
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
        Err(_) => return UserInputPathType::Missing
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
            Err(_) => {
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

    // TODO: ASAN_SYMBOLIZER_PATH=`which addr2line`

    match env::var("ASAN_OPTIONS") {
        Ok(val) => {
            println!("[!] Using ASAN_OPTIONS=\"{}\" that was set by the environment. This can change triage result accuracy", val);

            let re = Regex::new(r"abort_on_error=(1|true)").unwrap();
            match re.find(&val) {
                None => {
                    println!("[X] ASAN_OPTIONS does not have required abort_on_error=1 option");
                    return false;
                }
                _ => ()
            }
        }
        Err(_) => env::set_var("ASAN_OPTIONS", "abort_on_error=1:allow_user_segv_handler=0:symbolize=1,detect_leaks=0")
    }

    true
}

fn collect_input_testcases(processed_inputs: &mut Vec<UserInputPath>) -> Vec<Testcase> {
    let mut all_testcases = Vec::new();
    let mut ids = util::UniqueIdFactory::new();

    for input in processed_inputs {
        let pathStr = input.path.to_str().unwrap();

        match input.ty {
            UserInputPathType::Single => {
                println!("[+] Triaging single {}", pathStr);
                all_testcases.push(Testcase {
                    unique_id: ids.from_path(&input.path.as_path()),
                    path: input.path.clone()
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
                                // TODO: filter command (.*id:.*)
                                if tc.file_name().unwrap() == "README.txt" {
                                    continue;
                                }

                                valid += 1;
                                all_testcases.push(Testcase {
                                    unique_id: ids.from_path(&tc),
                                    path: tc
                                });
                            }
                        }

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

    all_testcases
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

    println!("AFLTriage v{} by Grant Hernandez\n", VERSION);

    let binary_args: Vec<&str> = args.values_of("command").unwrap().collect();

    // TODO: fix binary_args validation
    let gdb: GdbTriager = GdbTriager::new();

    if !sanity_check(&gdb, &binary_args) {
        return
    }

    println!("[+] Image triage cmdline: \"{}\"", binary_args.join(" "));

    let output = args.value_of("output").unwrap();

    let output_dir = match output {
        "-" => None,
        _ => {
            let d = std::path::PathBuf::from(output);
            match std::fs::create_dir(&d) {
                Err(e) => match e.kind() {
                    std::io::ErrorKind::AlreadyExists => (),
                    _ => {
                        println!("[X] Error creating output directory: {}", e);
                        return;
                    }
                },
                _ => ()
            }

            Some(d)
        }
    };

    match &output_dir { 
        Some(d) =>println!("[+] Reports will be output to directory \"{}\"", output),
        None => println!("[+] Reports output to terminal"),
    }

    let input_paths: Vec<&str> = args.values_of("input").unwrap().collect();

    let mut processed_inputs = Vec::new();

    for input in input_paths {
        let path = PathBuf::from(input);
        let ty = determine_input_type(&path);

        processed_inputs.push(UserInputPath {
            ty, path, fuzzer_stats: None
        });
    }

    let all_testcases = collect_input_testcases(&mut processed_inputs);

    if all_testcases.is_empty() {
        println!("No testcases found!");
        return
    }

    if args.is_present("dryrun") {
        println!("Exiting due to dry run");
        return
    }

    let debug = args.is_present("debug");
    let child_output = args.is_present("child_output");

    let requested_job_count = 20;
    let job_count = std::cmp::min(requested_job_count, all_testcases.len());

    // TODO: -n flag for parallelism
    rayon::ThreadPoolBuilder::new().num_threads(job_count).build_global().unwrap();

    let pb = ProgressBar::new((&all_testcases).len() as u64);

    let display_progress = isatty() && !output_dir.is_none() && !debug;

    if display_progress {
        pb.set_style(ProgressStyle::default_bar()
                     .template("[+] Triaging {spinner:.green} [{pos}/{len} {elapsed_precise}] [{bar:.cyan/blue}] {msg}")
                     .progress_chars("#>-"));
        pb.enable_steady_tick(200);

        pb.set_message(format!("Processing initial {} test cases", job_count).as_str());
    } else {
        println!("{}", format!("Processing initial {} test cases", job_count).as_str());
    }

    let write_message: Box<dyn Fn(String) + Sync> = match display_progress {
        true => Box::new(|msg| {
            pb.set_message(&msg)
        }),
        false => Box::new(|msg| { println!("{}", msg) })
    };

    let state = Arc::new(Mutex::new(TriageState {
        crashed: 0,
        no_crash: 0,
        errored: 0,
        crash_signature: HashSet::new(),
        unique_errors: HashMap::new(),
    }));

    let results : Vec<TestcaseResult> = all_testcases.par_iter().map(|testcase| {
        let path = testcase.path.to_str().unwrap();
        let result = process_test_case(&gdb, &binary_args, path, debug);

        let report = match &result {
            TriageResult::Crash(triage) => Some(report::format_text_report(&triage)),
            _ => None,
        };

        // do very little with this lock held. do not reorder
        let mut state = state.lock().unwrap();

        // TODO: display child-output even without a crash to help debug triage errors
        /*if child_output {
            println!("\nChild STDOUT:\n{}\n\nChild STDERR:\n{}\n",
                child.stdout, child.stderr);
        }*/

        match &result {
            TriageResult::NoCrash(child) => {
                state.no_crash += 1;

                write_message("No crash".into());
            }
            TriageResult::Crash(triage) => {
                let report = report.as_ref().unwrap();

                state.crashed += 1;

                write_message(format!("CRASH: {} {}", report.headline, testcase.unique_id));

                if !state.crash_signature.contains(&report.stackhash) {
                    state.crash_signature.insert(report.stackhash.to_string());

                    let mut text_report = format!(
                        "--- REPORT BEGIN ---\nTestcase: {}\nStack hash: {}\n\n\n{}\n\nbacktrace:\n{}\n",
                             path, report.stackhash, report.headline, report.backtrace);

                    if child_output {
                        text_report += &format!("\nChild STDOUT:\n{}\n\nChild STDERR:\n{}\n",
                            triage.child.stdout, triage.child.stderr);
                    }

                    text_report += "--- REPORT END ---";

                    if output_dir.is_none() {
                        write_message(text_report);
                    } else {
                        let output_dir = output_dir.as_ref().unwrap();
                        let report_filename = format!("afltriage_{}.txt", testcase.unique_id);

                        match std::fs::write(output_dir.join(report_filename), text_report) {
                            Err(e) => {
                                // TODO: notify / exit early
                                let failed_to_write = format!("Failed to write report: {}", e);
                                write_message(failed_to_write);
                            }
                            _ => (),
                        }
                    }
                }
            }
            TriageResult::Error(msg) => {
                state.errored += 1;

                if let Some(x) = state.unique_errors.get_mut(msg) {
                    *x += 1
                } else {
                    state.unique_errors.insert(msg.to_string(), 1);
                }

                write_message(format!("ERROR: {}", msg));
            }
        };

        if display_progress {
            pb.inc(1);
        }

        return TestcaseResult { testcase:path, result, report }
    }).collect::<Vec<TestcaseResult>>();

    pb.finish_and_clear();

    let state = state.lock().unwrap();
    let total = results.len();

    println!("[+] Triage stats [Crashes: {} (unique {}), No crash: {}, Errored: {}]",
        state.crashed, state.crash_signature.len(), state.no_crash, state.errored);

    if state.errored == total {
        // TODO: handle timeout/memory limit different vs. internal errors
        println!("[X] Something seems to be wrong during triage as all testcases errored.");
    } 

    if state.errored > 0 {
        println!("[!] There were {} error(s) ({} unique) during triage",
            state.errored, state.unique_errors.len());

        for (err, times) in &state.unique_errors {
            println!("[X] Triage error: {} (seen {} times)", err, times);
        }
    }

    if state.no_crash == total {
        println!("[!] None of the testcases crashed! Make sure that you are using the correct target command line and the right set of testcases");
    }
}
