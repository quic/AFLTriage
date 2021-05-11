# AFLTriage
A parallel crash triaging tool in Rust that uses GDB for backtracing.
It is designed to be standalone and not require any run-time dependencies, besides GDB.

Some notable features include:

* Crash deduplication
* ASAN support
* Source or binary-only text reports (with or without debug symbols)

## Usage

Usage of AFL triage is quite straightforward. You need your inputs to triage, an output directory for reports, and the binary and its arguments to triage.
Example:

```
$ afltriage -i fuzzing_directory -o reports ./target_binary --option-one @@
AFLTriage v0.1.2

[+] GDB is working (GNU gdb (Ubuntu 8.1.1-0ubuntu1) 8.1.1 - Python 3.6.9 (default, Jan 26 2021, 15:33:00))
[+] Using ASAN_SYMBOLIZER_PATH="/usr/bin/addr2line"
[+] Image triage cmdline: "./target_binary --option-one @@"
[+] Reports will be output to directory "reports"
[+] Triaging AFL directory fuzzing_directory/ (41 files)
[+] Triaging 41 testcases
[+] Using 24 threads to triage
[+] Triaging   [41/41 00:00:02] [####################] CRASH: ASAN detected heap-buffer-overflow in PFAL_PROC_HTON16 after a READ leading to SIGABRT (si_signo=6) / SI_TKILL (si_code=-6)
[+] Triage stats [Crashes: 25 (unique 12), No crash: 16, Errored: 0]
```

The `@@` is replaced with the path of the file to be triaged. AFLTriage will take care of the rest.

## Building and Running
Once you have cargo and rust installed, building and running is simple:

```
cd afltriage-rs/
cargo run --help

<compilation>

    Finished dev [unoptimized + debuginfo] target(s) in 0.33s
     Running `target/debug/afltriage --help`

afltriage 0.1.0
...
```

You can then run the triager on an afl directory:

```
cargo run -- -i afl_output_dir/ ./path_to_binary --binary args
```

Here is the extended usage statement for reference:

```
afltriage 0.1.2
Quickly triage and summarize crashing testcases

USAGE:
    afltriage -i <input>... -o <output> <command>...

FLAGS:
        --child-output    Include child output in triage reports.
        --debug           Enable low-level debugging of triage operations.
        --dry-run         Perform sanity checks and describe the inputs to be triaged.
    -h, --help            Prints help information
    -V, --version         Prints version information

OPTIONS:
    -i <input>...                 A path to a single testcase, directory of testcases, AFL directory, and/or directory
                                  of AFL directories to be triaged.
    -j <jobs>                     How many threads to use during triage.
        --output-format <ofmt>    The triage report output format. [default: text]  [possible values: text, markdown,
                                  json]
    -o <output>                   The output path for triage report files. Use '-' to print to console.

ARGS:
    <command>...    The binary executable and args to execute. Use '@@' as a placeholder for the path to the input
                    file.
```
