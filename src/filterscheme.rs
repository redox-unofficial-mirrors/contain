use libc::{getgid, getuid};
use libredox::errno::*;
use libredox::flag::{O_RDWR, O_WRONLY};
use libredox::Fd;
use log::{debug, error};
use redox_path::RedoxPath;
use redox_scheme::{scheme::SchemeSync, CallerCtx, OpenResult};
use syscall::{Error, Result};

use std::io;
use std::sync::{Arc, RwLock};

use crate::contain_config::ContainConfig;

struct IdGuard<const UID_NOT_GID: bool> {
    original: u32,
}

impl<const UID_NOT_GID: bool> IdGuard<UID_NOT_GID> {
    fn new(original: u32) -> IdGuard<UID_NOT_GID> {
        Self { original }
    }
}

impl<const UID_NOT_GID: bool> Drop for IdGuard<UID_NOT_GID> {
    fn drop(&mut self) {
        let res = if UID_NOT_GID {
            setreuid(self.original, self.original)
        } else {
            setregid(self.original, self.original)
        };
        if res.is_err() {
            if UID_NOT_GID {
                error!("CRITICAL: Failed to restore UID. UID may be stuck as another user.");
            } else {
                error!("CRITICAL: Failed to restore GID. GID may be stuck as another group.");
            }
        }
    }
}

fn setreuid(ruid: u32, euid: u32) -> Result<()> {
    let res = unsafe { libc::setreuid(ruid, euid) };
    if res < 0 {
        Err(Error::new(
            io::Error::last_os_error().raw_os_error().unwrap_or(EPERM),
        ))
    } else {
        Ok(())
    }
}

fn setregid(rgid: u32, egid: u32) -> Result<()> {
    let res = unsafe { libc::setregid(rgid, egid) };
    if res < 0 {
        Err(Error::new(
            io::Error::last_os_error().raw_os_error().unwrap_or(EPERM),
        ))
    } else {
        Ok(())
    }
}

/// Filter paths to only include the specified items.
/// Allow specified exact filename matches, regardless of types.
/// Allow paths starting with any of the specified directories.

pub struct FilterScheme {
    contained_ns: Fd,
    config: Arc<RwLock<ContainConfig>>,
}

impl FilterScheme {
    pub fn new(contained_ns: Fd, config: Arc<RwLock<ContainConfig>>) -> FilterScheme {
        FilterScheme {
            contained_ns,
            config,
        }
    }

    // Filter an absolute path (starts with a scheme name). Error on failure.
    fn is_allowed(&self, config: &ContainConfig, path: &str, flags: usize) -> Result<bool> {
        debug!("is_allowed: checking path={:?}, flags={:#x}", path, flags);
        debug!(
            "is_allowed config state: dirs={:?}, files={:?}, root={:?}",
            config.dirs, config.files, config.root
        );
        let path = path.to_string();
        let is_write = (flags & (O_WRONLY as usize | O_RDWR as usize)) != 0;

        if config
            .files
            .iter()
            .any(|match_path| crate::is_file_matched(&path, match_path))
        {
            debug!("is_allowed: matched files");
            Ok(true)
        } else if config.dirs.iter().any(|dir| crate::is_path_in_dir(&path, dir)) {
            debug!("is_allowed: matched dirs");
            Ok(true)
        } else if !is_write
            && (config
                .rofiles
                .iter()
                .any(|match_path| crate::is_file_matched(&path, match_path))
                || config.rodirs.iter().any(|dir| crate::is_path_in_dir(&path, dir)))
        {
            debug!("is_allowed: matched rofiles/rodirs");
            Ok(true)
        } else {
            debug!("canon_filter: failed/disallowed for path={:?}", path);
            Err(Error::new(EPERM))
        }
    }

    // Resolve path: if allowed, route to host scheme (/scheme/file/...).
    // If disallowed but root (chroot) is configured, fallback to contained_file scheme (/scheme/contained_file/...).
    fn resolve(&self, config: &ContainConfig, path: &str, flags: usize) -> Result<String> {
        debug!("resolve: path={:?}, flags={:#x}", path, flags);

        let abs_path = crate::ensure_scheme_path(path);
        let redox_path = RedoxPath::from_absolute(&abs_path).ok_or_else(|| {
            debug!(
                "resolve: RedoxPath::from_absolute failed for path={:?}",
                abs_path
            );
            Error::new(EINVAL)
        })?;

        let (scheme, reference) = redox_path.as_parts().ok_or_else(|| {
            debug!(
                "resolve: redox_path.as_parts() failed for path={:?}",
                abs_path
            );
            Error::new(EINVAL)
        })?;

        if config.pass_schemes.iter().any(|s| s == scheme.as_ref()) {
            debug!("resolve: matched pass_scheme {:?}", scheme.as_ref());
            return Ok(redox_path.to_standard().into_owned());
        }

        let ref_str = reference.as_ref().trim_start_matches('/');
        let full_path = redox_path.clone().to_standard().into_owned();

        if self.is_allowed(config, &full_path, flags).is_ok() {
            debug!("resolve: matched allowed host path={:?}", full_path);
            Ok(full_path)
        } else if config.root.is_some() {
            let contained_path = if ref_str.is_empty() {
                "/scheme/contained_file".to_string()
            } else {
                format!("/scheme/contained_file/{}", ref_str)
            };
            debug!(
                "resolve: fallback to contained_file path={:?}",
                contained_path
            );
            Ok(contained_path)
        } else {
            debug!("resolve: disallowed path={:?}", full_path);
            Err(Error::new(EPERM))
        }
    }
}

fn with_id_guards<F, R>(ctx: &CallerCtx, f: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    let original_gid = unsafe { getgid() };
    let original_uid = unsafe { getuid() };
    let _gid_guard = IdGuard::<false>::new(original_gid);
    let _uid_guard = IdGuard::<true>::new(original_uid);

    setregid(original_gid, ctx.gid as u32)?;
    setreuid(original_uid, ctx.uid as u32)?;

    f()
}

impl SchemeSync for FilterScheme {
    fn openat(
        &mut self,
        _fd: usize,
        path: &str,
        flags: usize,
        fcntl_flags: u32,
        ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        debug!(
            "FilterScheme::openat: path={:?}, flags={:#x}, fcntl_flags={:#x}, uid={}, gid={}",
            path, flags, fcntl_flags, ctx.uid, ctx.gid
        );
        let config = self.config.read().map_err(|e| {
            error!("open could not get read lock: {}", e);
            Error::new(ENOTRECOVERABLE)
        })?;

        with_id_guards(ctx, || {
            let res = self
                .resolve(&config, path, flags)
                .and_then(|resolved| {
                    debug!(
                        "FilterScheme::openat: opening resolved path={:?} via contained_ns",
                        resolved
                    );
                    self.contained_ns
                        .openat(&resolved, flags as i32, fcntl_flags)
                        .map_err(|e| {
                            debug!("FilterScheme::openat: contained_ns.openat error: {:?}", e);
                            syscall::Error::from(e)
                        })
                })
                .map(|fd| OpenResult::OtherScheme { fd: fd.into_raw() });
            debug!(
                "FilterScheme::openat result for {:?}: res_ok={}",
                path,
                res.is_ok()
            );
            res
        })
    }

    fn unlinkat(&mut self, _fd: usize, path: &str, flags: usize, ctx: &CallerCtx) -> Result<()> {
        debug!("unlink({})", path);

        let config = self.config.read().map_err(|e| {
            error!("unlink could not get read lock: {}", e);
            Error::new(ENOTRECOVERABLE)
        })?;

        with_id_guards(ctx, || {
            self.resolve(&config, path, 0)
                .and_then(|resolved| syscall::unlinkat(self.contained_ns.raw(), resolved, flags))
                .map(|_| ())
        })
    }
}
