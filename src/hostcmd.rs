use std::process::Command;

use anyhow::{Context, Result, bail};

pub fn powershell_available() -> bool {
    Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("$PSVersionTable.PSVersion.Major")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn powershell(command: &str) -> Result<String> {
    powershell_named("inline PowerShell", command)
}

pub fn powershell_named(name: &str, command: &str) -> Result<String> {
    powershell_with_env_named(name, command, &[])
}

pub fn powershell_with_env_named(
    name: &str,
    command: &str,
    envs: &[(&str, &str)],
) -> Result<String> {
    let mut process = Command::new("powershell.exe");
    process.arg("-NoProfile").arg("-Command").arg(command);
    for (key, value) in envs {
        process.env(key, value);
    }

    let output = process
        .output()
        .with_context(|| format!("run PowerShell command: {name}"))?;

    if !output.status.success() {
        bail!(
            "PowerShell command '{name}' failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
