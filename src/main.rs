use sysinfo::{Pid, System};

fn get_pids_of_process_with_args<S1: AsRef<str>, S2: AsRef<str>>(
    name: S1,
    args: &[S2],
) -> Vec<Pid> {
    let name = name.as_ref().to_lowercase();
    let mut system = System::new_all();
    system.refresh_processes();
    system
        .processes()
        .iter()
        .filter(|(_, process)| {
            process.name().to_lowercase() == name
                && process.cmd().len() == args.len() + 1
                && args.iter().enumerate().all(|(i, arg)| {
                    process.cmd()[i + 1].to_lowercase() == arg.as_ref().to_lowercase()
                })
        })
        .map(|(&pid, _)| pid)
        .collect()
}

fn main() {
    println!(
        "PIDs of processes with name 'rustdesk' and args ['--tray']: {:?}",
        get_pids_of_process_with_args("rustdesk.exe", &["--tray"])
    );
}
