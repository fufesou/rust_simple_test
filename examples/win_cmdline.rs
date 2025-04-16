
#[cfg(target_os = "windows")]
fn get_pids_of_process_with_args_by_wmic<S1: AsRef<str>, S2: AsRef<str>>(
    name: S1,
    args: &[S2],
) -> Vec<u32> {
    let name = name.as_ref().to_lowercase();
    let output = std::process::Command::new("wmic.exe")
        .args([
            "process",
            "where",
            &format!("name='{}'", name),
            "get",
            "commandline,processid",
            "/value",
        ])
        .output();
    output
        .map(|output| {
            let output = String::from_utf8_lossy(&output.stdout);
            let mut pids = Vec::new();
            let mut proc_found = false;
            for line in output.lines() {
                if line.starts_with("ProcessId=") {
                    if proc_found {
                        let pid = line["ProcessId=".len()..]
                            .trim()
                            .parse::<u32>()
                            .unwrap_or_default();
                        pids.push(pid);
                        proc_found = false;
                    }
                } else if line.starts_with("CommandLine=") {
                    proc_found = false;
                    let cmd = line["CommandLine=".len()..].trim().to_lowercase();
                    if args.is_empty() {
                        if cmd.ends_with(&name) || cmd.ends_with(&format!("{}\"", &name)) {
                            proc_found = true;
                        }
                    } else {
                        proc_found = args.iter().all(|arg| cmd.contains(arg.as_ref()));
                    }
                }
            }
            pids
        })
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn get_pids_of_process_with_first_arg_by_wmic<S1: AsRef<str>, S2: AsRef<str>>(
    name: S1,
    arg: S2,
) -> Vec<u32> {
    let name = name.as_ref().to_lowercase();
    let arg = arg.as_ref().to_lowercase();
    std::process::Command::new("wmic.exe")
        .args([
            "process",
            "where",
            &format!("name='{}'", name),
            "get",
            "commandline,processid",
            "/value",
        ])
        .output()
        .map(|output| {
            let output = String::from_utf8_lossy(&output.stdout);
            let mut pids = Vec::new();
            let mut proc_found = false;
            for line in output.lines() {
                if line.starts_with("ProcessId=") {
                    if proc_found {
                        let pid = line["ProcessId=".len()..]
                            .trim()
                            .parse::<u32>()
                            .unwrap_or_default();
                        pids.push(pid);
                        proc_found = false;
                    }
                } else if line.starts_with("CommandLine=") {
                    proc_found = false;
                    let cmd = line["CommandLine=".len()..].trim().to_lowercase();
                    if cmd.is_empty() {
                        continue;
                    }
                    if !arg.is_empty() && cmd.starts_with(&arg) {
                        proc_found = true;
                    } else {
                        for x in [&format!("{}\"", &name), &format!("{}", &name)] {
                            if cmd.contains(x) {
                                let cmd = cmd.split(x).collect::<Vec<_>>()[1..].join("");
                                if arg.is_empty() {
                                    if cmd.trim().is_empty() {
                                        proc_found = true;
                                    }
                                } else if cmd.trim().starts_with(&arg) {
                                    proc_found = true;
                                }
                                break;
                            }
                        }
                    }
                }
            }
            pids
        })
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn get_pids_with_first_arg_from_wmic_output(
    output: std::borrow::Cow<'_, str>,
    name: &str,
    arg: &str,
) -> Vec<sysinfo::Pid> {
    let mut pids = Vec::new();
    let mut proc_found = false;
    for line in output.lines() {
        if line.starts_with("ProcessId=") {
            if proc_found {
                if let Ok(pid) = line["ProcessId=".len()..].trim().parse::<u32>() {
                    pids.push(sysinfo::Pid::from_u32(pid));
                }
                proc_found = false;
            }
        } else if line.starts_with("CommandLine=") {
            proc_found = false;
            let cmd = line["CommandLine=".len()..].trim().to_lowercase();
            if cmd.is_empty() {
                continue;
            }
            if !arg.is_empty() && cmd.starts_with(arg) {
                proc_found = true;
            } else {
                for x in [&format!("{}\"", name), &format!("{}", name)] {
                    if cmd.contains(x) {
                        let cmd = cmd.split(x).collect::<Vec<_>>()[1..].join("");
                        if arg.is_empty() {
                            if cmd.trim().is_empty() {
                                proc_found = true;
                            }
                        } else if cmd.trim().starts_with(arg) {
                            proc_found = true;
                        }
                        break;
                    }
                }
            }
        }
    }
    pids
}

#[cfg(target_os = "windows")]
fn main() {
    // println!(
    //     "get pids_of_process_with_args_by_wmic: {:?}",
    //     get_pids_of_process_with_first_arg_by_wmic("rustdesk.exe", "--tray")
    // );
    // println!(
    //     "get pids_of_process_with_args_by_wmic: {:?}",
    //     get_pids_of_process_with_first_arg_by_wmic::<_, &str>("rustdesk.exe", "")
    // );

    let output = r#"
CommandLine=
ProcessId=33796

CommandLine=
ProcessId=34668

CommandLine="C:\Program Files\testapp\TestApp.exe" --tray
ProcessId=13728

CommandLine="C:\Program Files\testapp\TestApp.exe"
ProcessId=10136
    "#;
        let name = "testapp.exe";
        let arg = "--tray";
        let pids = get_pids_with_first_arg_from_wmic_output(
            String::from_utf8_lossy(output.as_bytes()),
            name,
            arg,
        );
        println!("pids: {:?}", pids);

        let arg = "";
        let pids = get_pids_with_first_arg_from_wmic_output(
            String::from_utf8_lossy(output.as_bytes()),
            name,
            arg,
        );
        println!("pids: {:?}", pids);

        let arg = "--other";
        let pids = get_pids_with_first_arg_from_wmic_output(
            String::from_utf8_lossy(output.as_bytes()),
            name,
            arg,
        );
        println!("pids: {:?}", pids);
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("Only available on Windows OS.");
}
