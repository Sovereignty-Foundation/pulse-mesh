// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Waits run off the event loop, each settling a promise.
//!
//! Each object that waits asynchronously (a `Receiver`, a `Channel`) gets a
//! thread of its own, started at its first asynchronous wait. The thread
//! runs the object's waits one at a time, in the order they were asked for,
//! so two receives asked for at once take two messages in order. A wait's
//! outcome reaches the event loop through the promise's threadsafe function
//! and is turned into JavaScript values there.
//!
//! The waits do not run on libuv's pool (napi's `AsyncTask`): a wait there
//! holds one of the pool's threads, four unless `UV_THREADPOOL_SIZE` says
//! otherwise, for as long as it waits, so four receives without a deadline
//! would stop every `fs`, `dns.lookup` and `crypto` call in the process.
//!
//! A promise is always settled: one whose wait never ran (its thread could
//! not be started) or ended in a panic is rejected when its wait is dropped.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};

use napi::bindgen_prelude::*;
use napi::{Env, JsDeferred, JsObject};

use crate::error::{into_js_error, Code};

/// A wait queued on an object's thread.
type Job = Box<dyn FnOnce() + Send>;

/// What a promise resolves with, made on the event loop.
type Resolver<D> = Box<dyn FnOnce(Env) -> Result<D> + Send>;

/// One object's thread and the count of its waits not yet settled.
pub(crate) struct Waiter {
    /// The thread's name, as a debugger or `top -H` shows it.
    thread_name: &'static str,
    /// The queue the thread reads, once it has started. Dropped with the
    /// object, which ends the thread once it has run what is queued.
    jobs: Option<mpsc::Sender<Job>>,
    /// Waits asked for and not yet settled.
    pending: Arc<AtomicUsize>,
}

impl Waiter {
    pub(crate) fn new(thread_name: &'static str) -> Self {
        Self {
            thread_name,
            jobs: None,
            pending: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Waits asked for and not yet settled. A count is dropped before its
    /// promise settles, so code that runs once a promise has settled sees
    /// it gone.
    pub(crate) fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    /// Run `wait` on this object's thread and return a promise of its
    /// outcome: a value is turned into JavaScript by `to_js`, on the event
    /// loop, and an error rejects the promise with its code.
    pub(crate) fn run<T, D, W, J>(&mut self, env: &Env, wait: W, to_js: J) -> Result<JsObject>
    where
        T: Send + 'static,
        D: ToNapiValue + 'static,
        W: FnOnce() -> Result<T, Code> + Send + 'static,
        J: FnOnce(Env, T) -> Result<D> + Send + 'static,
    {
        let (deferred, promise) = env.create_deferred::<D, Resolver<D>>()?;
        let settle = Settle::new(deferred, Arc::clone(&self.pending));
        let job: Job = Box::new(move || {
            let resolver: Resolver<D> = match wait() {
                Ok(value) => Box::new(move |env| to_js(env, value)),
                Err(error) => Box::new(move |env| Err(into_js_error(env, error))),
            };
            settle.resolve(resolver);
        });
        // A job that cannot be queued is dropped here, and its `Settle`
        // rejects the promise: the caller gets the promise either way.
        self.submit(job);
        Ok(promise)
    }

    /// Queue `job` on the thread, starting the thread if it has not started
    /// or has ended. A job that cannot be queued is dropped.
    fn submit(&mut self, job: Job) {
        let job = match &self.jobs {
            Some(jobs) => match jobs.send(job) {
                Ok(()) => return,
                // The thread ended (a wait panicked): start another.
                Err(mpsc::SendError(job)) => job,
            },
            None => job,
        };
        let (jobs, queue) = mpsc::channel::<Job>();
        let started = std::thread::Builder::new()
            .name(self.thread_name.to_owned())
            .spawn(move || {
                for job in queue {
                    job();
                }
            });
        self.jobs = None;
        if started.is_ok() && jobs.send(job).is_ok() {
            self.jobs = Some(jobs);
        }
    }
}

/// A promise to settle, and its object's count of waits not yet settled.
/// Dropped unsettled, it rejects the promise.
struct Settle<D: ToNapiValue + 'static> {
    deferred: Option<JsDeferred<D, Resolver<D>>>,
    pending: Arc<AtomicUsize>,
}

impl<D: ToNapiValue + 'static> Settle<D> {
    fn new(deferred: JsDeferred<D, Resolver<D>>, pending: Arc<AtomicUsize>) -> Self {
        pending.fetch_add(1, Ordering::AcqRel);
        Self {
            deferred: Some(deferred),
            pending,
        }
    }

    /// Settle the promise with what `resolver` makes on the event loop.
    fn resolve(mut self, resolver: Resolver<D>) {
        if let Some(deferred) = self.deferred.take() {
            self.pending.fetch_sub(1, Ordering::AcqRel);
            deferred.resolve(resolver);
        }
    }
}

impl<D: ToNapiValue + 'static> Drop for Settle<D> {
    fn drop(&mut self) {
        if let Some(deferred) = self.deferred.take() {
            self.pending.fetch_sub(1, Ordering::AcqRel);
            deferred.reject(Error::new(
                Status::GenericFailure,
                "the wait ended without an outcome: its thread could not be started or panicked",
            ));
        }
    }
}
