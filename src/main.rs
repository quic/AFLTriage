// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use clap::{arg_enum, Arg, ArgMatches, App, AppSettings, crate_version};
use std::path::PathBuf;
use is_executable::IsExecutable;
use std::collections::{HashSet, HashMap};
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
    report: TestcaseResult
}

enum TestcaseResult {
    NoCrash(),
    Crash(CrashReport),
    Error(String)
}

fn process_test_case(gdb: &GdbTriager, binary_args: &Vec<&str>, testcase: &str) -> TestcaseResult {
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
            return TestcaseResult::Error(format!("Failed to triage: {}", e));
        },
    };

    if res.current_tid == -1 {
        return TestcaseResult::NoCrash();
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
                let frames = &thread.backtrace[0..];
                let headline = format!("CRASH: tid {} in {}",
                         res.current_tid, frames.get(0).unwrap().symbol.function_name.as_str());

                let mut major_hash = md5::Context::new();
                let mut backtrace = String::new();

                for (i, fr) in frames.iter().enumerate() {
                    major_hash.consume(fr.pretty_address.as_bytes());
                    backtrace += &format!("#{:<2} pc {:<08x} {} ({})\n",
                        i, fr.address, fr.module, fr.symbol.function_name);
                }

                return TestcaseResult::Crash(
                    CrashReport {
                        headline, backtrace,
                        stackhash: String::from(format!("{:x}", major_hash.compute()))
                    }
                );
            }
        }

        return TestcaseResult::Error("Crashing thread not found in backtrace".into());
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

    let all_testcases = collect_input_testcases(&mut processed_inputs);

    if all_testcases.is_empty() {
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

    let display_progress = isatty();
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

    let results : Vec<TriageState> = all_testcases.par_iter().map(|testcase| {
        let path = testcase.path.to_str().unwrap();
        let result = process_test_case(&gdb, &binary_args, path);

        match &result {
            TestcaseResult::NoCrash() => write_message("No crash".into()),
            TestcaseResult::Crash(report) => write_message(format!("CRASH: {}", report.headline)),
            TestcaseResult::Error(msg) => write_message(format!("ERROR: {}", msg))
        }

        if display_progress {
            pb.inc(1);
        }

        return TriageState { testcase:path, report:result }
    }).collect::<Vec<TriageState>>();

    pb.finish();

    let mut crashes = 0;
    let mut no_crash = 0;
    let mut errored = 0;
    let total = results.len();

    let mut crash_signature = HashSet::new();
    let mut unique_errors = HashMap::new();

    for state in &results {
        match &state.report  {
            TestcaseResult::NoCrash() => no_crash += 1,
            TestcaseResult::Crash(report) => {
                //let formatted = format_report(&state);
                crashes += 1;

                if !crash_signature.contains(&report.stackhash) {
                    println!("--- --- --- --- --- ---\nTestcase: {}\nStack hash: {}\n\n\n{}\n\nbacktrace:\n{}\n",
                             state.testcase, report.stackhash, report.headline, report.backtrace);
                    crash_signature.insert(report.stackhash.to_string());
                }
            },
            TestcaseResult::Error(msg) => {
                if let Some(x) = unique_errors.get_mut(&msg) {
                    *x += 1
                } else {
                    unique_errors.insert(msg, 1);
                }

                // TODO: accumulate all unique error cases
                errored += 1;
            }
        }
    }

    println!("[+] Triage stats [Crashes: {} (unique {}), No crash: {}, Errored: {}]",
        crashes, crash_signature.len(), no_crash, errored);

    if errored == total {
        println!("[X] Something seems to be wrong during triage as all testcases errored. Enable --debug for more information");
    } else if errored > 0 {
        println!("[!] There was {} error(s) during triage", errored);

        for (err, times) in unique_errors {
            println!("[X] Triage error: {} (seen {} times)", err, times);
        }
    }

    if no_crash == total {
        println!("[!] None of the testcases crashed! Make sure that you are using the correct target command line and the right set of testcases");
    }

    // TODO: special cases - no crashes, all errored
}
