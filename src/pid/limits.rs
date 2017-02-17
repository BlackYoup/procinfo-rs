//! Process limits informations from `/proc/[pid]/limits`.

use std::fs::File;
use std::io::Result;
use std::str::{self};
use time::Duration;

use libc::pid_t;
use nom::{
    IResult,
    line_ending,
    is_space
};

use parsers::{
    map_result,
    parse_isize,
    parse_word,
    read_to_end
};

named!(parse_limit_value<&[u8], isize>,
    alt!(map!(tag_s!("unlimited"), |_| LIMITS_INFINITY) | parse_isize)
);

named!(parse_limit_line<&[u8],(isize,isize,Option<LimitUnit>)>,
    do_parse!(
        take_until!("  ") >>
        take_while!(is_space) >>
        soft_limit: parse_limit_value >>
        take_while!(is_space) >>
        hard_limit: parse_limit_value >>
        take_while!(is_space) >>
        unit: map!(opt!(parse_word), unit_types) >>
        take_while!(is_space) >>
        line_ending >>

        ((soft_limit, hard_limit, unit))
    )
);

/// A constant to represent the "unlimited" value
pub const LIMITS_INFINITY: isize = -1;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LimitUnit{
    Seconds,
    Bytes,
    Processes,
    Files,
    Locks,
    Other(String),
    Signals,
    Us
}

/// A struct to hold limits and unit of the limit type
/// A soft_limit or hard_limit equals to -1 means its "unlimited".
#[derive(Debug, PartialEq, Eq)]
pub struct Limit{
    pub soft_limit: isize,
    pub hard_limit: isize,
    pub unit: Option<LimitUnit>
}

#[derive(Debug, PartialEq, Eq)]
pub struct LimitDuration{
    pub soft_limit: Duration,
    pub hard_limit: Duration,
    pub unit: Option<LimitUnit>
}

/// Process limits information
/// See man 2 getrlimit
#[derive(Debug, PartialEq, Eq)]
pub struct Limits{
    /// The maximum CPU time a process can use, in seconds
    pub max_cpu_time          : LimitDuration, // TODO: values are seconds, use Duration
    /// The maximum size of files that the process may create
    pub max_file_size         : Limit,
    /// The maximum size of the process's data segment
    pub max_data_size         : Limit,
    /// The  maximum size of the process stack
    pub max_stack_size        : Limit,
    /// Maximum size of a core file
    pub max_core_file_size    : Limit,
    /// Specifies  the limit of the process's resident set
    pub max_resident_set      : Limit,
    /// The maximum number of processes (or, more precisely on Linux, threads)
    /// that can be created for the real user ID of the calling process
    pub max_processes         : Limit,
    ///  Specifies  a value one greater than the maximum file descriptor
    ///  number that can be opened by this process
    pub max_open_files        : Limit,
    /// The maximum number of bytes of memory that may be locked into RAM
    pub max_locked_memory     : Limit,
	/// The maximum size of the process's virtual memory (address space)
    pub max_address_space     : Limit,
	/// A limit on the combined number of locks and leases that this process may
    /// establish
    pub max_file_locks        : Limit,
	/// Specifies  the  limit  on the number of signals that may be queued for the real user ID of
    /// the calling process
    pub max_pending_signals   : Limit,
	/// Specifies the limit on the number of bytes that can be allocated for POSIX message queues
    /// for the real user ID of the calling process
    pub max_msgqueue_size     : Limit,
	/// Specifies  a  ceiling  to  which the process's nice value can be raised
    pub max_nice_priority     : Limit,
	/// Specifies a limit on the amount of CPU time that a process scheduled
    /// under a real-time scheduling policy may consume without making a blocking
    /// system call
    pub max_realtime_priority : Limit, // TODO: values are microseconds, use Duration,
	/// Specifies a ceiling on the real-time priority that may be set for this process
    pub max_realtime_timeout  : LimitDuration
}

fn parse_limits(input: &[u8]) -> IResult<&[u8], Limits> {
    let rest = input;
    let (rest, _)                     = try_parse!(rest, take_until_and_consume!(&b"\n"[..]));
    let (rest, max_cpu_time)          = try_parse!(rest, map!(parse_limit_line, to_limit_duration));
    let (rest, max_file_size)         = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_data_size)         = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_stack_size)        = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_core_file_size)    = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_resident_set)      = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_processes)         = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_open_files)        = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_locked_memory)     = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_address_space)     = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_file_locks)        = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_pending_signals)   = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_msgqueue_size)     = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_nice_priority)     = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_realtime_priority) = try_parse!(rest, map!(parse_limit_line, to_limit));
    let (rest, max_realtime_timeout)  = try_parse!(rest, map!(parse_limit_line, to_limit_duration));

    IResult::Done(rest, Limits{
        max_cpu_time          : max_cpu_time,
        max_file_size         : max_file_size,
        max_data_size         : max_data_size,
        max_stack_size        : max_stack_size,
        max_core_file_size    : max_core_file_size,
        max_resident_set      : max_resident_set,
        max_processes         : max_processes,
        max_open_files        : max_open_files,
        max_locked_memory     : max_locked_memory,
        max_address_space     : max_address_space,
        max_file_locks        : max_file_locks,
        max_pending_signals   : max_pending_signals,
        max_msgqueue_size     : max_msgqueue_size,
        max_nice_priority     : max_nice_priority,
        max_realtime_priority : max_realtime_priority,
        max_realtime_timeout  : max_realtime_timeout
    })
}

fn limits_file(file: &mut File) -> Result<Limits> {
    let mut buf = [0; 2048];
    map_result(parse_limits(try!(read_to_end(file, &mut buf))))
}

pub fn limits(pid: pid_t) -> Result<Limits> {
    limits_file(&mut try!(File::open(&format!("/proc/{}/limits", pid))))
}

pub fn limits_self() -> Result<Limits> {
    limits_file(&mut try!(File::open("/proc/self/limits")))
}

fn unit_types(unit: Option<String>) -> Option<LimitUnit> {
    unit.and_then(|u| {
        match u.as_ref() {
            "bytes"      => Some(LimitUnit::Bytes),
            "files"      => Some(LimitUnit::Files),
            "locks"      => Some(LimitUnit::Locks),
            "processes"  => Some(LimitUnit::Processes),
            "seconds"    => Some(LimitUnit::Seconds),
            "signals"    => Some(LimitUnit::Signals),
            "us"         => Some(LimitUnit::Us),
            _            => Some(LimitUnit::Other(u))
        }
    })
}

fn to_limit((soft_limit, hard_limit, unit): (isize, isize, Option<LimitUnit>)) -> Limit{
    Limit{
        soft_limit: soft_limit,
        hard_limit: hard_limit,
        unit: unit
    }
}

fn to_limit_duration((soft_limit, hard_limit, unit): (isize, isize, Option<LimitUnit>)) -> LimitDuration{
    if let Some(u) = unit.clone(){
        match u{
            LimitUnit::Seconds => {
                LimitDuration{
                    soft_limit: Duration::seconds(soft_limit as i64),
                    hard_limit: Duration::seconds(hard_limit as i64),
                    unit: unit
                }
            },
            LimitUnit::Us => {
                LimitDuration{
                    soft_limit: Duration::microseconds(soft_limit as i64),
                    hard_limit: Duration::microseconds(hard_limit as i64),
                    unit: unit
                }
            },
            _ => panic!(format!("LimitUnit {:?} is not of type Seconds or Us", unit))
        }
    } else {
        panic!(format!("Limit unit is None"));
    }
}

#[cfg(test)]
pub mod tests{
    use time::Duration;
    use parsers::tests::unwrap;
    use super::{LIMITS_INFINITY, LimitUnit, parse_limits};

    #[test]
    fn test_parse_limits(){
        let text = b"Limit                     Soft Limit           Hard Limit           Units         \n
Max cpu time              unlimited            unlimited            seconds       \n
Max file size             unlimited            unlimited            bytes         \n
Max data size             unlimited            unlimited            bytes         \n
Max stack size            8388608              unlimited            bytes         \n
Max core file size        unlimited            unlimited            bytes         \n
Max resident set          unlimited            unlimited            bytes         \n
Max processes             63632                63632                processes     \n
Max open files            1024                 4096                 files         \n
Max locked memory         65536                65536                bytes         \n
Max address space         unlimited            unlimited            bytes         \n
Max file locks            unlimited            unlimited            locks         \n
Max pending signals       63632                63632                signals       \n
Max msgqueue size         819200               819200               bytes         \n
Max nice priority         0                    0                                  \n
Max realtime priority     0                    0                                  \n
Max realtime timeout      unlimited            unlimited            us            \n";

        let limits = unwrap(parse_limits(text));

        assert_eq!(Duration::seconds(-1), limits.max_cpu_time.soft_limit);
        assert_eq!(Duration::seconds(-1), limits.max_cpu_time.hard_limit);
        assert_eq!(Some(LimitUnit::Seconds), limits.max_cpu_time.unit);

        assert_eq!(LIMITS_INFINITY, limits.max_file_size.soft_limit);
        assert_eq!(LIMITS_INFINITY, limits.max_file_size.hard_limit);
        assert_eq!(Some(LimitUnit::Bytes), limits.max_file_size.unit);

        assert_eq!(LIMITS_INFINITY, limits.max_data_size.soft_limit);
        assert_eq!(LIMITS_INFINITY, limits.max_data_size.hard_limit);
        assert_eq!(Some(LimitUnit::Bytes), limits.max_data_size.unit);

        assert_eq!(8388608, limits.max_stack_size.soft_limit);
        assert_eq!(LIMITS_INFINITY, limits.max_stack_size.hard_limit);
        assert_eq!(Some(LimitUnit::Bytes), limits.max_stack_size.unit);

        assert_eq!(LIMITS_INFINITY, limits.max_core_file_size.soft_limit);
        assert_eq!(LIMITS_INFINITY, limits.max_core_file_size.hard_limit);
        assert_eq!(Some(LimitUnit::Bytes), limits.max_core_file_size.unit);

        assert_eq!(LIMITS_INFINITY, limits.max_resident_set.soft_limit);
        assert_eq!(LIMITS_INFINITY, limits.max_resident_set.hard_limit);
        assert_eq!(Some(LimitUnit::Bytes), limits.max_resident_set.unit);

        assert_eq!(63632, limits.max_processes.soft_limit);
        assert_eq!(63632, limits.max_processes.hard_limit);
        assert_eq!(Some(LimitUnit::Processes), limits.max_processes.unit);

        assert_eq!(1024, limits.max_open_files.soft_limit);
        assert_eq!(4096, limits.max_open_files.hard_limit);
        assert_eq!(Some(LimitUnit::Files), limits.max_open_files.unit);

        assert_eq!(65536, limits.max_locked_memory.soft_limit);
        assert_eq!(65536, limits.max_locked_memory.hard_limit);
        assert_eq!(Some(LimitUnit::Bytes), limits.max_locked_memory.unit);

        assert_eq!(LIMITS_INFINITY, limits.max_address_space.soft_limit);
        assert_eq!(LIMITS_INFINITY, limits.max_address_space.hard_limit);
        assert_eq!(Some(LimitUnit::Bytes), limits.max_address_space.unit);

        assert_eq!(LIMITS_INFINITY, limits.max_file_locks.soft_limit);
        assert_eq!(LIMITS_INFINITY, limits.max_file_locks.hard_limit);
        assert_eq!(Some(LimitUnit::Locks), limits.max_file_locks.unit);

        assert_eq!(63632, limits.max_pending_signals.soft_limit);
        assert_eq!(63632, limits.max_pending_signals.hard_limit);
        assert_eq!(Some(LimitUnit::Signals), limits.max_pending_signals.unit);

        assert_eq!(819200, limits.max_msgqueue_size.soft_limit);
        assert_eq!(819200, limits.max_msgqueue_size.hard_limit);
        assert_eq!(Some(LimitUnit::Bytes), limits.max_msgqueue_size.unit);

        assert_eq!(0, limits.max_nice_priority.soft_limit);
        assert_eq!(0, limits.max_nice_priority.hard_limit);
        assert_eq!(None, limits.max_nice_priority.unit);

        assert_eq!(0, limits.max_realtime_priority.soft_limit);
        assert_eq!(0, limits.max_realtime_priority.hard_limit);
        assert_eq!(None, limits.max_realtime_priority.unit);

        assert_eq!(Duration::microseconds(-1), limits.max_realtime_timeout.soft_limit);
        assert_eq!(Duration::microseconds(-1), limits.max_realtime_timeout.hard_limit);
        assert_eq!(Some(LimitUnit::Us), limits.max_realtime_timeout.unit);
    }
}
