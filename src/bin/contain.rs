use std::process::Command;
use std::str::FromStr;

use log::{debug, error, LevelFilter};
use redox_log::{OutputBuilder, RedoxLogger};

use contain::{run_contained, ContainConfig};

use clap::{Args, Parser};
use redox_users::All;

/// Contain: Limit the access to the file system.
/// May be used like "chroot" or simply as a filter.
/// Note that programs that get the path to something may not work when
/// chroot'd, so chroot mode is not recommended for interactive use.
///
/// If a `root` is specified, it becomes the location of "/".
/// If there is a root, `cwd` is optional, with a default value of "/".
///
/// `cwd` is interpreted as relative to root,
/// unless it is in one of the allowed directories.
///
/// If there is no root, cwd is mandatory
/// and is added to the allowed directories.
#[derive(Parser, Debug)]
struct ContainArgs {
    #[command(flatten)]
    working_dir: WorkingDir,

    /// Don't include default files or schemes
    #[arg(long)]
    no_default: bool,

    /// The toml/ron file containing the default config
    #[arg(short, long)]
    config: Option<String>,

    /// Set User ID for the command to execute
    #[arg(short, long)]
    user: Option<String>,

    /// Schemes to allow unchanged (don't include trailing ":")
    #[arg(short, long)]
    pass_schemes: Vec<String>,

    /// Schemes to be filtered (only specified paths)
    #[arg(short, long)]
    sandbox_schemes: Vec<String>,

    /// Add a file or match to allow, format "/scheme/scheme-name/dir/dir/file"
    #[arg(short, long)]
    file: Vec<String>,

    /// Include directory(s) or prefix to allow unchanged, format "/scheme/scheme-name/dir/dir"
    #[arg(short, long)]
    dir: Vec<String>,

    /// Debug level ("error", "warn", "info", "debug", or "trace")
    #[arg(long)]
    debug: Option<String>,

    /// Command to be executed, and its args - evaluated after chroot (if any)
    /// If a user is specified, the command is optional
    command: Vec<String>,
}

#[derive(Args, Debug)]
#[group(required = true)]
struct WorkingDir {
    /// "chroot", using the specified directory as root (optional)
    #[arg(short, long)]
    root: Option<String>,

    /// Working directory - required if there is no chroot
    #[arg(short, long)]
    cwd: Option<String>,
}

const CONFIG_FILE: &str = "/scheme/file/etc/contain.toml";

fn setup_logging(level: LevelFilter) -> Option<&'static RedoxLogger> {
    let mut logger = RedoxLogger::new().with_output(
        OutputBuilder::stderr()
            .with_filter(level) // limit global output to important info
            .with_ansi_escape_codes()
            .flush_on_newline(true)
            .build(),
    );

    #[cfg(target_os = "redox")]
    match OutputBuilder::in_redox_logging_scheme("contain", "contain", "contain.log") {
        Ok(b) => {
            logger = logger.with_output(
                // TODO: Add a configuration file for this
                b.with_filter(level).flush_on_newline(true).build(),
            )
        }
        Err(error) => eprintln!("contain: failed to create contain.log: {}", error),
    }

    #[cfg(target_os = "redox")]
    match OutputBuilder::in_redox_logging_scheme("contain", "contain", "contain.ansi.log") {
        Ok(b) => {
            logger = logger.with_output(
                b.with_filter(LevelFilter::Info)
                    .with_ansi_escape_codes()
                    .flush_on_newline(true)
                    .build(),
            )
        }
        Err(error) => eprintln!("contain: failed to create contain.ansi.log: {}", error),
    }

    match logger.enable() {
        Ok(logger_ref) => {
            if level > LevelFilter::Error {
                eprintln!("contain: enabled logger, level {}", level);
            }
            Some(logger_ref)
        }
        Err(error) => {
            eprintln!("contain: failed to set default logger: {}", error);
            None
        }
    }
}

pub fn main() {
    let contain_args = ContainArgs::parse();

    let log_level = if contain_args.debug.is_some() {
        LevelFilter::from_str(contain_args.debug.as_ref().unwrap()).unwrap_or(LevelFilter::Error)
    } else {
        LevelFilter::Error
    };

    setup_logging(log_level);

    debug!("contain_args: {:?}", contain_args);

    let mut config = if contain_args.no_default && contain_args.config.is_none() {
        ContainConfig::default()
    } else {
        let config_file = if let Some(config_file) = contain_args.config.as_ref() {
            config_file.clone()
        } else {
            CONFIG_FILE.to_string()
        };
        ContainConfig::from_file(&config_file)
            .map_err(|e| {
                error!("could not read config from file {}: {}", CONFIG_FILE, e);
                let _ = std::process::exit(1);
            })
            .unwrap()
    };

    debug!("config from file {}: {:?}", CONFIG_FILE, config);

    let root = contain_args
        .working_dir
        .root
        .as_deref()
        .map(contain::ensure_scheme_path);
    let cwd = contain_args
        .working_dir
        .cwd
        .as_deref()
        .map(contain::ensure_scheme_path);
    assert!(root.is_some() || cwd.is_some()); // or both

    for s in contain_args.pass_schemes {
        config.pass_schemes.push(s.to_string());
    }
    for s in contain_args.sandbox_schemes {
        config.sandbox_schemes.push(s.to_string());
    }
    for f in contain_args.file {
        config.add_file(&f);
    }
    for d in contain_args.dir {
        config.add_dir(&d);
    }
    // If there is a chroot, cwd is relative to root
    // or otherwise allowed.
    // If not, cwd is automatically allowed.
    if let Some(ref cwd_path) = cwd {
        if root.is_none() {
            config.add_dir(cwd_path);
        }
    }

    if let Some(ref r) = root {
        config.add_chroot(r);
    }

    assert!(config.files.iter().all(|f| f.starts_with("/scheme/")));
    assert!(config.dirs.iter().all(|d| d.starts_with("/scheme/")));
    assert!(config
        .sandbox_schemes
        .iter()
        .all(|s| !s.contains([':', '/'])));
    assert!(config.pass_schemes.iter().all(|s| !s.contains([':', '/'])));

    if contain_args.user.is_none() && contain_args.command.len() == 0 {
        error!("User was not specified and no command was provided.");
        let _ = std::process::exit(1);
    }

    let mut command = if !contain_args.command.is_empty() {
        let mut cmd_iter = contain_args.command.iter();
        let prog = cmd_iter.next().unwrap();
        let prog_path = if prog.starts_with('/') {
            prog.to_string()
        } else {
            format!("/scheme/file/bin/{}", prog)
        };
        let mut command = Command::new(prog_path);
        for arg in cmd_iter {
            command.arg(&arg);
        }
        command
    } else {
        Command::new("/scheme/file/bin/login")
    };

    let target_cwd = cwd.as_deref().unwrap_or("/");
    command.current_dir(contain::ensure_scheme_path(target_cwd));

    if contain_args.user.is_some() {
        let all_users = redox_users::AllUsers::authenticator(redox_users::Config::default())
            .map_err(|e| {
                error!("failed to get authenticator, {}", e);
                let _ = std::process::exit(1);
            })
            .unwrap();
        let user = all_users
            .get_by_name(contain_args.user.as_ref().unwrap())
            .ok_or_else(|| {
                error!("could not get user {}", contain_args.user.as_ref().unwrap());
                let _ = std::process::exit(1);
            })
            .unwrap();

        if contain_args.command.is_empty() {
            command = user.shell_cmd();
        }

        if cwd.is_none() {
            command.current_dir(contain::ensure_scheme_path(&user.home));
            config.add_dir(&user.home)
        }
    }

    let _ = run_contained(config, command);
}
