// Copyright (c) 2021, Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use strum::IntoStaticStr;
use signal_hook::consts::signal::*;

// How the Linux kernel assigns SI code namespaces
//#define SI_FROMUSER(siptr)	((siptr)->si_code <= 0)
//#define SI_FROMKERNEL(siptr)	((siptr)->si_code > 0)

pub fn si_code_to_string(signal: &str, code: i8) -> &'static str {
    if code <= 0 {
        if let Ok(s) = SI_Generic::try_from(code) {
            return s.into();
        }
    } else if signal == "SIGILL" {
        if let Ok(s) = SI_ILL::try_from(code) {
            return s.into();
        }
    } else if signal == "SIGFPE" {
        if let Ok(s) = SI_FPE::try_from(code) {
            return s.into();
        }
    } else if signal == "SIGBUS" {
        if let Ok(s) = SI_BUS::try_from(code) {
            return s.into();
        }
    } else if signal == "SIGSEGV" {
        if let Ok(s) = SI_SEGV::try_from(code) {
            return s.into();
        }
    }

    "SI_UNKNOWN"
}

pub fn signal_to_string(code: i32) -> &'static str {
    match code {
        SIGABRT => stringify!(SIGABRT),
        SIGALRM => stringify!(SIGALRM),
        SIGBUS => stringify!(SIGBUS),
        SIGCHLD => stringify!(SIGCHLD),
        SIGCONT => stringify!(SIGCONT),
        SIGFPE => stringify!(SIGFPE),
        SIGHUP => stringify!(SIGHUP),
        SIGILL => stringify!(SIGILL),
        SIGINT => stringify!(SIGINT),
        SIGIO => stringify!(SIGIO),
        SIGKILL => stringify!(SIGKILL),
        SIGPIPE => stringify!(SIGPIPE),
        SIGPROF => stringify!(SIGPROF),
        SIGQUIT => stringify!(SIGQUIT),
        SIGSEGV => stringify!(SIGSEGV),
        SIGSTOP => stringify!(SIGSTOP),
        SIGSYS => stringify!(SIGSYS),
        SIGTERM => stringify!(SIGTERM),
        SIGTRAP => stringify!(SIGTRAP),
        SIGTSTP => stringify!(SIGTSTP),
        SIGTTIN => stringify!(SIGTTIN),
        SIGTTOU => stringify!(SIGTTOU),
        SIGURG => stringify!(SIGURG),
        SIGUSR1 => stringify!(SIGUSR1),
        SIGUSR2 => stringify!(SIGUSR2),
        SIGVTALRM => stringify!(SIGVTALRM),
        SIGWINCH => stringify!(SIGWINCH),
        SIGXCPU => stringify!(SIGXCPU),
        SIGXFSZ => stringify!(SIGXFSZ),
        _ => "UNKNOWN",
    }
}

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(IntoStaticStr, TryFromPrimitive)]
#[repr(i8)]
enum SI_Generic {
    SI_USER = 0,
    SI_KERNEL = -128,
    SI_QUEUE = -1,
    SI_TIMER = -2,
    SI_MESGQ = -3,
    SI_ASYNCIO = -4,
    SI_SIGIO = -5,
    SI_TKILL = -6,
    SI_DETHREAD = -7,
    SI_ASYNCNL = -60,
}

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(IntoStaticStr, TryFromPrimitive)]
#[repr(i8)]
enum SI_ILL {
    ILL_ILLOPC = 1,
    ILL_ILLOPN = 2,
    ILL_ILLADR = 3,
    ILL_ILLTRP = 4,
    ILL_PRVOPC = 5,
    ILL_PRVREG = 6,
    ILL_COPROC = 7,
    ILL_BADSTK = 8,
    ILL_BADIADDR = 9,
    __ILL_BREAK = 10,
    __ILL_BNDMOD = 11,
}

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(IntoStaticStr, TryFromPrimitive)]
#[repr(i8)]
enum SI_FPE {
    FPE_INTDIV = 1,
    FPE_INTOVF = 2,
    FPE_FLTDIV = 3,
    FPE_FLTOVF = 4,
    FPE_FLTUND = 5,
    FPE_FLTRES = 6,
    FPE_FLTINV = 7,
    FPE_FLTSUB = 8,
    __FPE_DECOVF = 9,
    __FPE_DECDIV = 10,
    __FPE_DECERR = 11,
    __FPE_INVASC = 12,
    __FPE_INVDEC = 13,
    FPE_FLTUNK = 14,
    FPE_CONDTRAP = 15,
}

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(IntoStaticStr, TryFromPrimitive)]
#[repr(i8)]
enum SI_SEGV {
    SEGV_MAPERR = 1,
    SEGV_ACCERR = 2,
    SEGV_BNDERR = 3,
    SEGV_PKUERR = 4,
    SEGV_ACCADI = 5,
    SEGV_ADIDERR = 6,
    SEGV_ADIPERR = 7,
    SEGV_MTEAERR = 8,
    SEGV_MTESERR = 9,
}

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(IntoStaticStr, TryFromPrimitive)]
#[repr(i8)]
enum SI_BUS {
    BUS_ADRALN = 1,
    BUS_ADRERR = 2,
    BUS_OBJERR = 3,
    BUS_MCEERR_AR = 4,
    BUS_MCEERR_AO = 5,
}
