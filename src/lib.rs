mod contain_config;
mod contain_thread;
mod filterscheme;
mod runner;

pub use contain_config::ContainConfig;
pub use contain_thread::ContainThread;
pub use runner::{run_contained, run_in_namespace, run_not_contained};

pub fn ensure_scheme_path(path: &str) -> String {
    if let Some(redox_path) = redox_path::RedoxPath::from_absolute(path) {
        if let Some((scheme, reference)) = redox_path.as_parts() {
            let ref_str = reference.as_ref().trim_start_matches('/');
            if ref_str.is_empty() {
                format!("/scheme/{}", scheme.as_ref())
            } else {
                format!("/scheme/{}/{}", scheme.as_ref(), ref_str)
            }
        } else {
            redox_path.to_standard().into_owned()
        }
    } else if path.starts_with('/') {
        format!("/scheme/file{}", path)
    } else {
        format!("/scheme/file/{}", path)
    }
}

pub fn is_path_in_dir(path: &str, dir: &str) -> bool {
    let clean_dir = dir.trim_end_matches('/');
    let clean_path = path.trim_end_matches('/');

    clean_path == clean_dir || path.starts_with(&format!("{}/", clean_dir))
}

pub fn is_file_matched(path: &str, file_pattern: &str) -> bool {
    path.trim_end_matches('/') == file_pattern.trim_end_matches('/')
}

// TODO: Check ownership of files (e.g. /scheme/pty/5) before making them visible
// TODO: Add tests
// TODO: Implement delete/drop of namespace in the kernel
// TODO: Re-implement path filtering when Rust Path supports Redox
// TODO: Discuss the future of the chroot-incompatible fpath syscall,
// since it doesn't work for forwarded descriptors

pub const CONTAIN_EXEC_FAIL_EXIT: i32 = 13;

pub type ContainResult<T> = core::result::Result<T, ContainError>;

#[derive(Debug)]
pub enum ContainError {
    ParseError,
    ConfigError,
    IoError(std::io::Error),
    SyscallError(syscall::Error),
    PoisonError,
    ThreadError,
}

impl ContainError {
    pub fn io_error(e: std::io::Error) -> Self {
        Self::IoError(e)
    }

    pub fn syscall_error(e: syscall::Error) -> Self {
        Self::SyscallError(e.into())
    }

    pub fn poison_error<T>(_e: std::sync::PoisonError<T>) -> Self {
        Self::PoisonError
    }
}

impl std::fmt::Display for ContainError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}
