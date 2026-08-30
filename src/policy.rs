use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};

#[derive(Debug, Clone)]
pub enum ExecPolicy {
    Unrestricted,
    /// Exact canonical top-level executables resolved when shellvibe starts.
    Allow(BTreeSet<PathBuf>),
    /// Name/path deny rules. This remains a guardrail, not a sandbox.
    Deny {
        names: BTreeSet<String>,
        paths: BTreeSet<PathBuf>,
    },
}

impl ExecPolicy {
    pub fn allow(items: Vec<String>, cwd: &Path) -> anyhow::Result<Self> {
        if items.is_empty() {
            bail!("allow policy must contain at least one executable");
        }
        let mut paths = BTreeSet::new();
        for item in items {
            paths.insert(resolve_executable(item.trim(), cwd)?);
        }
        Ok(Self::Allow(paths))
    }

    pub fn deny(items: Vec<String>, cwd: &Path) -> anyhow::Result<Self> {
        if items.is_empty() {
            bail!("deny policy must contain at least one executable");
        }
        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for item in items {
            let item = item.trim();
            if item.is_empty() {
                bail!("executable policy entries must not be empty");
            }
            if let Some(name) = executable_identity(Path::new(item)) {
                names.insert(name);
            }
            if let Ok(path) = resolve_executable(item, cwd) {
                paths.insert(path);
            }
        }
        Ok(Self::Deny { names, paths })
    }

    pub const fn is_restricted(&self) -> bool {
        !matches!(self, Self::Unrestricted)
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Unrestricted => "unrestricted",
            Self::Allow(_) => "allow-list",
            Self::Deny { .. } => "deny-list",
        }
    }

    /// Authorize only the top-level executable shellvibe itself starts.
    /// Permitted programs can still spawn subprocesses or access arbitrary resources.
    pub fn authorize(&self, requested: &str, cwd: &Path) -> anyhow::Result<PathBuf> {
        if matches!(self, Self::Unrestricted) {
            bail!("internal error: executable authorization only applies in restricted mode");
        }
        let resolved = resolve_executable(requested, cwd)?;
        match self {
            Self::Allow(allowed) if !allowed.contains(&resolved) => {
                bail!(
                    "executable '{}' is not in the --allow-exec list",
                    resolved.display()
                )
            }
            Self::Deny { names, paths } => {
                let requested_name = executable_identity(Path::new(requested));
                let resolved_name = executable_identity(&resolved);
                if paths.contains(&resolved)
                    || requested_name
                        .as_ref()
                        .is_some_and(|name| names.contains(name))
                    || resolved_name
                        .as_ref()
                        .is_some_and(|name| names.contains(name))
                {
                    bail!(
                        "executable '{}' is denied by --deny-exec",
                        resolved.display()
                    );
                }
                Ok(resolved)
            }
            _ => Ok(resolved),
        }
    }
}

fn resolve_executable(requested: &str, cwd: &Path) -> anyhow::Result<PathBuf> {
    if requested.is_empty() {
        bail!("argv[0] must not be empty");
    }
    let requested_path = Path::new(requested);
    if requested_path.components().count() > 1 || requested_path.is_absolute() {
        let path = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            cwd.join(requested_path)
        };
        return canonical_executable(path, requested);
    }

    let path_env = env::var_os("PATH").unwrap_or_default();
    for dir in env::split_paths(&path_env) {
        for candidate in candidates(&dir, requested) {
            if is_executable_file(&candidate) {
                return canonical_executable(candidate, requested);
            }
        }
    }
    bail!("executable '{requested}' was not found in shellvibe's PATH")
}

fn canonical_executable(path: PathBuf, requested: &str) -> anyhow::Result<PathBuf> {
    if !is_executable_file(&path) {
        bail!(
            "executable '{requested}' does not resolve to an executable file: {}",
            path.display()
        );
    }
    std::fs::canonicalize(&path)
        .with_context(|| format!("failed to canonicalize executable {}", path.display()))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    executable_permissions(&metadata, path)
}

#[cfg(unix)]
fn executable_permissions(metadata: &std::fs::Metadata, _path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(windows)]
fn executable_permissions(_metadata: &std::fs::Metadata, path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "exe" | "com"))
}

#[cfg(not(any(unix, windows)))]
fn executable_permissions(_metadata: &std::fs::Metadata, _path: &Path) -> bool {
    true
}

#[cfg(windows)]
fn candidates(dir: &Path, name: &str) -> Vec<PathBuf> {
    if Path::new(name).extension().is_some() {
        return vec![dir.join(name)];
    }
    // Restricted mode promises direct process creation without a command
    // interpreter. Batch files require cmd.exe semantics, so deliberately
    // exclude .cmd/.bat even when PATHEXT advertises them.
    let pathext = env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.COM".into());
    pathext
        .split(';')
        .filter(|ext| matches!(ext.to_ascii_lowercase().as_str(), ".exe" | ".com"))
        .map(|ext| dir.join(format!("{name}{ext}")))
        .collect()
}

#[cfg(not(windows))]
fn candidates(dir: &Path, name: &str) -> Vec<PathBuf> {
    vec![dir.join(name)]
}

fn executable_identity(path: &Path) -> Option<String> {
    let file = path.file_name()?.to_string_lossy();
    identity_suffix(file.as_ref())
}

#[cfg(windows)]
fn identity_suffix(file: &str) -> Option<String> {
    let lowered = file.to_ascii_lowercase();
    for suffix in [".exe", ".com", ".cmd", ".bat"] {
        if let Some(stripped) = lowered.strip_suffix(suffix) {
            return Some(stripped.to_string());
        }
    }
    Some(lowered)
}

#[cfg(not(windows))]
fn identity_suffix(file: &str) -> Option<String> {
    Some(file.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_is_not_restricted() {
        assert!(!ExecPolicy::Unrestricted.is_restricted());
    }

    #[test]
    fn basename_identity_is_stable() {
        assert_eq!(
            executable_identity(Path::new("/usr/bin/git")).as_deref(),
            Some("git")
        );
    }
}
