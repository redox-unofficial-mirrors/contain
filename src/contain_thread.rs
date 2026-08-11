use std::cell::RefCell;
use std::convert::Into;
use std::sync::{Arc, LockResult, RwLock, RwLockReadGuard};
use std::thread::{self, JoinHandle};

use event::{EventFlags, EventQueue};
use libredox::Fd;
use log::{debug, error, warn};
use redox_scheme::{wrappers::ReadinessBased, Socket};

use crate::contain_config::ContainConfig;
use crate::filterscheme::FilterScheme;
use crate::{ContainError, ContainResult};

pub struct ContainThread {
    config: Arc<RwLock<ContainConfig>>,
    namespace: Fd,
    shutdown_pipe: usize,
    thread_handle: JoinHandle<()>,
}

impl ContainThread {
    // Create the namespace and spawn the scheme manager(s).
    // We use an RwLock for the config so we can start with
    // the basic space and add the user directory after.
    pub fn new(config: ContainConfig) -> ContainResult<Self> {
        event::user_data! {
            enum EventSource {
                Pipe,
                FilterScheme,
            }
        }

        let config_arc = Arc::new(RwLock::new(config));
        let config_lock = config_arc.read().map_err(|e| {
            error!("could not get config lock: {}", e);
            ContainError::poison_error(e)
        })?;

        let mut scheme_ptrs: Vec<ioslice::IoSlice> =
            Vec::with_capacity(config_lock.pass_schemes.len());
        for scheme in config_lock
            .pass_schemes
            .iter()
            .chain(config_lock.sandbox_schemes.iter())
        {
            scheme_ptrs.push(ioslice::IoSlice::new(scheme.as_bytes()));
        }

        let new_ns = Fd::new(libredox::call::mkns(&scheme_ptrs).map_err(|e| {
            error!("could not create namespace, {}", e);
            ContainError::syscall_error(e.into())
        })?);

        if let Some(ref root_path) = config_lock.root {
            debug!(
                "ContainThread::new: registering root path {:?} as contained_file scheme",
                root_path
            );
            let root_fd = Fd::open(root_path, libredox::flag::O_DIRECTORY, 0).map_err(|e| {
                error!("could not open root path {:?}: {}", root_path, e);
                ContainError::syscall_error(e.into())
            })?;

            libredox::call::register_scheme_to_ns(new_ns.raw(), "contained_file", root_fd.raw())
                .map_err(|e| {
                    error!("could not register root scheme to namespace: {}", e);
                    ContainError::syscall_error(e.into())
                })?;
        }
        let socket = Socket::nonblock().map_err(|e| {
            error!("could not create scheme: {}", e);
            ContainError::syscall_error(e)
        })?;

        let contain_fd = Fd::new(socket.create_this_scheme_fd(0, 0, 0, 0).map_err(|e| {
            error!("could not create this scheme fd: {}", e);
            ContainError::syscall_error(e)
        })?);

        let event_queue = EventQueue::<EventSource>::new().map_err(|e| {
            error!("could not open event queue");
            ContainError::syscall_error(e.into())
        })?;
        event_queue
            .subscribe(
                socket.inner().raw(),
                EventSource::FilterScheme,
                EventFlags::READ,
            )
            .map_err(|e| {
                error!("could not subscribe filter scheme socket");
                ContainError::syscall_error(e.into())
            })?;

        // Create a pipe to request shutdown when the user command completes
        let mut pipes = [0; 2];

        match unsafe {
            libc::pipe2(
                pipes.as_mut_ptr(),
                libredox::flag::O_CLOEXEC | libredox::flag::O_NONBLOCK,
            )
        } {
            0 => Ok(()),
            -1 => {
                error!("could not create pipe");
                Err(ContainError::io_error(std::io::Error::last_os_error()))
            }
            _ => unreachable!(),
        }?;

        debug!("pipes {:?}", &pipes);
        let [read_pipe, write_pipe] = pipes;
        let read_pipe = read_pipe as usize;
        let write_pipe = write_pipe as usize;
        event_queue
            .subscribe(read_pipe, EventSource::Pipe, EventFlags::READ)
            .map_err(|e| {
                error!(
                    "could not subscribe for event on pipe fd {}, {}",
                    read_pipe, e
                );
                ContainError::syscall_error(e.into())
            })?;

        event_queue
            .subscribe(
                socket.inner().raw(),
                EventSource::FilterScheme,
                EventFlags::READ,
            )
            .map_err(|e| {
                error!("could not subscribe filter scheme socket");
                ContainError::syscall_error(e.into())
            })?;

        drop(config_lock);

        let config_arc_clone = config_arc.clone();
        let scheme_thread = thread::spawn(move || {
            debug!("scheme_thread: started event loop");
            let mut handler = ReadinessBased::new(&socket, 16);
            let scheme = RefCell::new(FilterScheme::new(new_ns, config_arc_clone));
            'events: loop {
                let Ok(event) = event_queue.next_event() else {
                    warn!("scheme_thread: event queue returned no data / error");
                    break 'events;
                };
                match event.user_data {
                    EventSource::Pipe => {
                        debug!("scheme_thread: got shutdown pipe event, exiting loop");
                        break 'events;
                    }
                    EventSource::FilterScheme => {
                        debug!("scheme_thread: got filter scheme event");
                        match handler.read_requests() {
                            Ok(true) => {
                                debug!("scheme_thread: processing requests");
                                handler.process_requests(|| scheme.borrow_mut());
                                if let Err(err) = handler.write_responses() {
                                    error!("scheme_thread: failed to write responses: {:?}", err);
                                }
                                debug!("scheme_thread: finished processing requests");
                            }
                            Ok(false) => {
                                warn!("scheme_thread: handler.read_requests returned EOF (false), breaking loop");
                                break 'events;
                            }
                            Err(err) => {
                                error!("scheme_thread: could not read syscall request: {:?}", err);
                                break 'events;
                            }
                        }
                    }
                }
            }
            warn!("scheme_thread: event loop exited, thread terminating!");
        });

        Ok(Self {
            config: config_arc,
            namespace: contain_fd,
            shutdown_pipe: write_pipe,
            thread_handle: scheme_thread,
        })
    }

    pub fn namespace(&self) -> usize {
        self.namespace.raw()
    }

    pub fn thread(&self) -> &JoinHandle<()> {
        &self.thread_handle
    }

    pub fn config(&self) -> LockResult<RwLockReadGuard<'_, ContainConfig>> {
        self.config.read()
    }
}

impl Drop for ContainThread {
    // Shutdown the thread by sending a message on the shutdown pipe
    // TODO: Implement drop of namespace
    fn drop(&mut self) {
        debug!("ContainThread::drop: sending shutdown signal to scheme thread");

        let res = libredox::call::write(self.shutdown_pipe, "shutdown scheme".as_bytes());
        debug!(
            "ContainThread::drop: write to shutdown pipe result: {:?}",
            res
        );
    }
}
