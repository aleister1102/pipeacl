const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(not(windows))]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "-v" || args[1] == "--version") {
        println!("pipeacl {}", VERSION);
        return;
    }
    eprintln!("pipeacl is Windows-only");
    std::process::exit(1);
}

#[cfg(windows)]
mod windows_impl {
    use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::process::ExitCode;
use std::ptr;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;

const WRITABLE_MASK: u32 = GENERIC_WRITE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_DATA;

#[derive(Default)]
struct Args {
    verbose: bool,
    json: bool,
    filter_writable: bool,
}

struct PipeInfo {
    name: String,
    writable: bool,
    sid: String,
    access_str: String,
    sddl: String,
}

fn main() -> ExitCode {
    let args = parse_args();

    let pipes = match enumerate_pipes() {
        Ok(p) if p.is_empty() => return ExitCode::from(2),
        Ok(p) => p,
        Err(_) => return ExitCode::from(1),
    };

    let mut sid_cache: HashMap<String, String> = HashMap::new();
    let mut results: Vec<PipeInfo> = Vec::new();

    for pipe_name in pipes {
        if let Some(info) = get_pipe_info(&pipe_name, &mut sid_cache, args.verbose) {
            if !args.filter_writable || info.writable {
                results.push(info);
            }
        }
    }

    if results.is_empty() {
        return ExitCode::from(2);
    }

    if args.json {
        print_json(&results);
    } else {
        print_default(&results, args.verbose);
    }

    ExitCode::SUCCESS
}

fn parse_args() -> Args {
    let mut args = Args::default();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--version" => {
                println!("pipeacl {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-v" => args.verbose = true,
            "-j" => args.json = true,
            "-f" => args.filter_writable = true,
            "writable" => {}
            _ => {}
        }
    }
    args
}

fn enumerate_pipes() -> Result<Vec<String>, ()> {
    let mut pipes = Vec::new();
    let pipe_dir = r"\\.\pipe\";
    let search_path: Vec<u16> = format!("{}*", pipe_dir)
        .encode_utf16()
        .chain(Some(0))
        .collect();

    unsafe {
        let mut find_data: WIN32_FIND_DATAW = std::mem::zeroed();
        let handle = FindFirstFileW(search_path.as_ptr(), &mut find_data);

        if handle == INVALID_HANDLE_VALUE {
            return Err(());
        }

        loop {
            let len = find_data
                .cFileName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(find_data.cFileName.len());
            let name = OsString::from_wide(&find_data.cFileName[..len]);
            if let Some(name_str) = name.to_str() {
                if !name_str.is_empty() {
                    pipes.push(format!("{}{}", pipe_dir, name_str));
                }
            }

            if FindNextFileW(handle, &mut find_data) == 0 {
                break;
            }
        }
        FindClose(handle);
    }

    Ok(pipes)
}

fn get_pipe_info(
    pipe_path: &str,
    sid_cache: &mut HashMap<String, String>,
    get_sddl: bool,
) -> Option<PipeInfo> {
    let pipe_wide: Vec<u16> = pipe_path.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let handle = CreateFileW(
            pipe_wide.as_ptr(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );

        if handle == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut sd: *mut SECURITY_DESCRIPTOR = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();

        let result = GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd as *mut _ as *mut *mut _,
        );

        CloseHandle(handle);

        if result != ERROR_SUCCESS {
            return None;
        }

        let (writable, sid_str, access_str) = analyze_dacl(dacl, sid_cache);

        let sddl = if get_sddl {
            get_sddl_string(sd as *const _)
        } else {
            String::new()
        };

        if !sd.is_null() {
            LocalFree(sd as *mut _);
        }

        let name = pipe_path.strip_prefix(r"\\.\pipe\").unwrap_or(pipe_path);

        Some(PipeInfo {
            name: format!(r"\\.\pipe\{}", name),
            writable,
            sid: sid_str,
            access_str,
            sddl,
        })
    }
}

fn analyze_dacl(dacl: *mut ACL, sid_cache: &mut HashMap<String, String>) -> (bool, String, String) {
    if dacl.is_null() {
        return (false, String::new(), String::new());
    }

    unsafe {
        let ace_count = (*dacl).AceCount as u32;
        let mut writable = false;
        let mut best_sid = String::new();
        let mut best_access = String::new();

        for i in 0..ace_count {
            let mut ace: *mut std::ffi::c_void = ptr::null_mut();
            if GetAce(dacl, i, &mut ace) == 0 {
                continue;
            }

            let ace_header = ace as *const ACE_HEADER;
            let ace_type = (*ace_header).AceType;

            if ace_type == 0x00 {  // ACCESS_ALLOWED_ACE_TYPE
                let allowed_ace = ace as *const ACCESS_ALLOWED_ACE;
                let mask = (*allowed_ace).Mask;
                let sid = &(*allowed_ace).SidStart as *const u32 as PSID;

                if (mask & WRITABLE_MASK) != 0 {
                    writable = true;
                    let sid_string = sid_to_string(sid);
                    let name = sid_cache
                        .entry(sid_string.clone())
                        .or_insert_with(|| lookup_sid_name(sid).unwrap_or_else(|| sid_string.clone()))
                        .clone();

                    let access = format_access_mask(mask);
                    if best_sid.is_empty() || is_interesting_sid(sid) {
                        best_sid = sid_string;
                        best_access = format!("{}:{}", name, access);
                    }
                }
            }
        }

        (writable, best_sid, best_access)
    }
}

fn is_interesting_sid(sid: PSID) -> bool {
    unsafe {
        IsWellKnownSid(sid, WinBuiltinUsersSid) != 0
            || IsWellKnownSid(sid, WinWorldSid) != 0
            || IsWellKnownSid(sid, WinAuthenticatedUserSid) != 0
    }
}

fn format_access_mask(mask: u32) -> String {
    if (mask & GENERIC_ALL) != 0 {
        return "F".to_string();
    }
    let mut perms = String::new();
    if (mask & FILE_READ_DATA) != 0 || (mask & GENERIC_READ) != 0 {
        perms.push('R');
    }
    if (mask & WRITABLE_MASK) != 0 {
        perms.push('W');
    }
    if perms.is_empty() {
        format!("0x{:X}", mask)
    } else {
        perms
    }
}

fn sid_to_string(sid: PSID) -> String {
    unsafe {
        let mut sid_str: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut sid_str) != 0 {
            let len = (0..).take_while(|&i| *sid_str.add(i) != 0).count();
            let slice = std::slice::from_raw_parts(sid_str, len);
            let result = String::from_utf16_lossy(slice);
            LocalFree(sid_str as *mut _);
            result
        } else {
            String::new()
        }
    }
}

fn lookup_sid_name(sid: PSID) -> Option<String> {
    unsafe {
        let mut name_len: u32 = 256;
        let mut domain_len: u32 = 256;
        let mut name_buf: Vec<u16> = vec![0; name_len as usize];
        let mut domain_buf: Vec<u16> = vec![0; domain_len as usize];
        let mut sid_type: SID_NAME_USE = 0;

        if LookupAccountSidW(
            ptr::null(),
            sid,
            name_buf.as_mut_ptr(),
            &mut name_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        ) != 0
        {
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
            if domain.is_empty() {
                Some(name)
            } else {
                Some(format!("{}\\{}", domain, name))
            }
        } else {
            None
        }
    }
}

fn get_sddl_string(sd: *const SECURITY_DESCRIPTOR) -> String {
    unsafe {
        let mut sddl: *mut u16 = ptr::null_mut();
        let mut sddl_len: u32 = 0;

        if ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd as *mut _,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            &mut sddl_len,
        ) != 0
        {
            let len = (0..).take_while(|&i| *sddl.add(i) != 0).count();
            let slice = std::slice::from_raw_parts(sddl, len);
            let result = String::from_utf16_lossy(slice);
            LocalFree(sddl as *mut _);
            result
        } else {
            String::new()
        }
    }
}

fn print_default(results: &[PipeInfo], verbose: bool) {
    for info in results {
        if verbose && !info.sddl.is_empty() {
            println!("{}   {}   {}", info.name, info.access_str, info.sddl);
        } else {
            println!("{}   {}", info.name, info.access_str);
        }
    }
}

fn print_json(results: &[PipeInfo]) {
    print!("[");
    for (i, info) in results.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!(
            r#"{{"pipe":"{}","writable":{},"sid":"{}"}}"#,
            info.name.replace('\\', "\\\\"),
            info.writable,
            info.sid
        );
    }
    println!("]");
}

pub fn run() -> std::process::ExitCode {
    main()
}
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    windows_impl::run()
}
