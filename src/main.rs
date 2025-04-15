fn get_pids_of_process_with_args_by_wmic<S1: AsRef<str>, S2: AsRef<str>>(
    name: S1,
    args: &[S2],
) -> Vec<u32> {
    let name = name.as_ref().to_lowercase();
    let output = std::process::Command::new("wmic")
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

fn get_pids_of_process_with_first_arg_by_wmic<S1: AsRef<str>, S2: AsRef<str>>(
    name: S1,
    arg: S2,
) -> Vec<u32> {
    let name = name.as_ref().to_lowercase();
    let arg = arg.as_ref().to_lowercase();
    std::process::Command::new("wmic")
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

fn main() {
    println!(
        "get pids_of_process_with_args_by_wmic: {:?}",
        get_pids_of_process_with_first_arg_by_wmic("rustdesk.exe", "--tray")
    );
    println!(
        "get pids_of_process_with_args_by_wmic: {:?}",
        get_pids_of_process_with_first_arg_by_wmic::<_, &str>("rustdesk.exe", "")
    );
}
