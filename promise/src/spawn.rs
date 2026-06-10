use anyhow::{anyhow, Result};
use async_executor::Executor;
use flume::{bounded, unbounded, Receiver, TryRecvError};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

pub use async_task::{Runnable, Task};
pub type SpawnFunc = Box<dyn FnOnce() + Send>;
pub type ScheduleFunc = Box<dyn Fn(Runnable) + Send + Sync + 'static>;

fn no_scheduler_configured(_: Runnable) {
    panic!("no scheduler has been configured");
}

lazy_static::lazy_static! {
    static ref ON_MAIN_THREAD: Mutex<ScheduleFunc> = Mutex::new(Box::new(no_scheduler_configured));
    static ref ON_MAIN_THREAD_LOW_PRI: Mutex<ScheduleFunc> = Mutex::new(Box::new(no_scheduler_configured));
    static ref SCOPED_EXECUTOR: Mutex<Option<Arc<Executor<'static>>>> = Mutex::new(None);
    /// termob fork: process-global `!Send` executor for `spawn_local_inline`
    /// futures (lua `Rc<Lua>`, mux `Rc`/`Arc<dyn Pane>`). Lives behind a Mutex
    /// because the schedule path may be reached from any thread, but the
    /// contained `LocalExecutor` is only ever POLLED on the main thread
    /// (`drive_local_executor`, called from `SimpleExecutor::tick`). The
    /// executor itself is `!Send`/`!Sync`; the `Arc<Mutex<..>>` makes the
    /// HANDLE shareable so a cross-thread wake can ring the main-loop doorbell.
    /// `spawn`/`try_tick` only touch it on the main thread, so no `!Send`
    /// data crosses threads.
    static ref LOCAL_EXECUTOR: Arc<LocalExecutorCell> = Arc::new(LocalExecutorCell::new());
}

/// Holds the main-thread `!Send` executor plus a `Send` doorbell so a
/// cross-thread wake can ask the main loop to poll it. See [`LOCAL_EXECUTOR`].
struct LocalExecutorCell {
    /// The `!Send` executor. `unsafe impl Send/Sync` below is sound because
    /// every access (`spawn`, `try_tick`) is gated to the main thread; the
    /// cell only exists so the *handle* (Arc) can be cloned into a `Send`
    /// doorbell closure that never touches the executor itself.
    exec: async_executor::LocalExecutor<'static>,
    /// Set by [`set_local_doorbell`] from `SimpleExecutor::new`. Rung on every
    /// local-task wake so the (possibly blocked-on-recv) main loop wakes and
    /// drains the local executor on the main thread.
    doorbell: Mutex<Option<Box<dyn Fn() + Send + Sync + 'static>>>,
}

// SAFETY: `LocalExecutor` is `!Send`/`!Sync` because it must be polled on one
// thread. We uphold that invariant manually: `spawn` and `try_tick` are only
// called from the main thread (see `spawn_local_inline`/`drive_local_executor`,
// both of which run on the `run_executor_loop` thread). The `Send`/`Sync` impl
// only enables sharing the Arc handle so a `Send` doorbell closure can ring the
// main loop from a reactor thread — that closure never accesses `exec`.
unsafe impl Send for LocalExecutorCell {}
unsafe impl Sync for LocalExecutorCell {}

impl LocalExecutorCell {
    fn new() -> Self {
        Self {
            exec: async_executor::LocalExecutor::new(),
            doorbell: Mutex::new(None),
        }
    }

    fn ring_doorbell(&self) {
        if let Ok(guard) = self.doorbell.lock() {
            if let Some(bell) = guard.as_ref() {
                bell();
            }
        }
    }
}

/// Install the doorbell that local-task wakes ring to drive the main loop.
/// Called once by `SimpleExecutor::new` (or any embedder owning the main loop).
pub fn set_local_doorbell<F: Fn() + Send + Sync + 'static>(doorbell: F) {
    if let Ok(mut guard) = LOCAL_EXECUTOR.doorbell.lock() {
        *guard = Some(Box::new(doorbell));
    }
}

/// Poll the main-thread `!Send` executor until no task is immediately runnable.
/// MUST be called only on the main thread (the one that runs the executor
/// loop). `SimpleExecutor::tick` calls this after every channel event so that
/// `spawn_local_inline` futures — including ones woken from a reactor thread
/// (e.g. `smol::Timer`) — are polled here instead of being run inline on the
/// waking thread (which would poll `!Send` data off-thread → UB/abort).
pub fn drive_local_executor() {
    while LOCAL_EXECUTOR.exec.try_tick() {}
}

static SCHEDULER_CONFIGURED: AtomicBool = AtomicBool::new(false);

fn schedule_runnable(runnable: Runnable, high_pri: bool) {
    let func = if high_pri {
        ON_MAIN_THREAD.lock()
    } else {
        ON_MAIN_THREAD_LOW_PRI.lock()
    }
    .unwrap();
    func(runnable);
}

pub fn is_scheduler_configured() -> bool {
    SCHEDULER_CONFIGURED.load(Ordering::Relaxed)
}

/// Set callbacks for scheduling normal and low priority futures.
/// Why this and not "just tokio"?  In a GUI application there is typically
/// a special GUI processing loop that may need to run on the "main thread",
/// so we can't just run a tokio/mio loop in that context.
/// This particular crate has no real knowledge of how that plumbing works,
/// it just provides the abstraction for scheduling the work.
/// This function allows the embedding application to set that up.
pub fn set_schedulers(main: ScheduleFunc, low_pri: ScheduleFunc) {
    *ON_MAIN_THREAD.lock().unwrap() = Box::new(main);
    *ON_MAIN_THREAD_LOW_PRI.lock().unwrap() = Box::new(low_pri);
    SCHEDULER_CONFIGURED.store(true, Ordering::Relaxed);
}

/// Spawn a new thread to execute the provided function.
/// Returns a JoinHandle that implements the Future trait
/// and that can be used to await and yield the return value
/// from the thread.
/// Can be called from any thread.
pub fn spawn_into_new_thread<F, T>(f: F) -> Task<Result<T>>
where
    F: FnOnce() -> Result<T>,
    F: Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = bounded(1);

    // Holds the waker that may later observe
    // during the Future::poll call.
    struct WakerHolder {
        waker: Mutex<Option<Waker>>,
    }

    let holder = Arc::new(WakerHolder {
        waker: Mutex::new(None),
    });

    let thread_waker = Arc::clone(&holder);
    std::thread::spawn(move || {
        // Run the thread
        let res = f();
        // Pass the result back
        tx.send(res).unwrap();
        // If someone polled the thread before we got here,
        // they will have populated the waker; extract it
        // and wake up the scheduler so that it will poll
        // the result again.
        let mut waker = thread_waker.waker.lock().unwrap();
        if let Some(waker) = waker.take() {
            waker.wake();
        }
    });

    struct PendingResult<T> {
        rx: Receiver<Result<T>>,
        holder: Arc<WakerHolder>,
    }

    impl<T> std::future::Future for PendingResult<T> {
        type Output = Result<T>;

        fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context) -> Poll<Self::Output> {
            match self.rx.try_recv() {
                Ok(res) => Poll::Ready(res),
                Err(TryRecvError::Empty) => {
                    let mut waker = self.holder.waker.lock().unwrap();
                    waker.replace(cx.waker().clone());
                    Poll::Pending
                }
                Err(TryRecvError::Disconnected) => {
                    Poll::Ready(Err(anyhow!("thread terminated without providing a result")))
                }
            }
        }
    }

    spawn_into_main_thread(PendingResult { rx, holder })
}

fn get_scoped() -> Option<Arc<Executor<'static>>> {
    SCOPED_EXECUTOR.lock().unwrap().as_ref().map(Arc::clone)
}

/// Spawn a future into the main thread; it will be polled in the
/// main thread.
/// This function can be called from any thread.
/// If you are on the main thread already, consider using
/// spawn() instead to lift the `Send` requirement.
pub fn spawn_into_main_thread<F, R>(future: F) -> Task<R>
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    if let Some(executor) = get_scoped() {
        return executor.spawn(future);
    }
    let (runnable, task) = async_task::spawn(future, |runnable| schedule_runnable(runnable, true));
    runnable.schedule();
    task
}

/// Spawn a future into the main thread; it will be polled in
/// the main thread in the low priority queue--all other normal
/// priority items will be drained before considering low priority
/// spawns.
/// If you are on the main thread already, consider using `spawn_with_low_priority`
/// instead to lift the `Send` requirement.
pub fn spawn_into_main_thread_with_low_priority<F, R>(future: F) -> Task<R>
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    if let Some(executor) = get_scoped() {
        return executor.spawn(future);
    }
    let (runnable, task) = async_task::spawn(future, |runnable| schedule_runnable(runnable, false));
    runnable.schedule();
    task
}

/// Spawn a future with normal priority.
///
/// termob fork: `spawn_local` → `spawn` (Send). Upstream wezterm uses
/// `spawn_local` because their `window` crate guarantees single-thread
/// spawn+poll. termob's promise tick thread is separate, so Send is
/// required. Call sites with `!Send` futures (lua `Rc<Lua>`) should use
/// `spawn_local_inline` instead.
pub fn spawn<F, R>(future: F) -> Task<R>
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let (runnable, task) = async_task::spawn(future, |runnable| schedule_runnable(runnable, true));
    runnable.schedule();
    task
}

/// Spawn a future with low priority; it will be polled only after
/// all other normal priority items are processed.
///
/// termob fork: `spawn_local` → `spawn` (Send). See `spawn()` doc.
pub fn spawn_with_low_priority<F, R>(future: F) -> Task<R>
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let (runnable, task) = async_task::spawn(future, |runnable| schedule_runnable(runnable, false));
    runnable.schedule();
    task
}

/// Spawn a `!Send` future (lua `Rc<Lua>`, mux `Rc`/`Arc<dyn Pane>`) onto the
/// process-global main-thread [`LOCAL_EXECUTOR`].
///
/// **Must be called on the main thread** (the one that runs the executor loop
/// — `run_executor_loop` / `SimpleExecutor::tick`). `spawn` itself only
/// enqueues; the future is POLLED on the main thread when [`drive_local_executor`]
/// runs (driven by `SimpleExecutor::tick`).
///
/// termob fork history: this previously used `async_task::spawn_local` with a
/// `|r| r.run()` schedule closure, which ran the runnable INLINE on whatever
/// thread woke it. For a future that pends on a cross-thread wake (e.g.
/// `smol::Timer::after` woken by the async-io reactor thread), that polled the
/// `!Send` future OFF the main thread → undefined behaviour / abort under
/// `panic=abort`. Routing through `LocalExecutor` fixes this: cross-thread
/// wakes ring the main-loop doorbell, and the actual poll happens on the main
/// thread via `try_tick`.
pub fn spawn_local_inline<F, R>(future: F) -> Task<R>
where
    F: Future<Output = R> + 'static,
    R: 'static,
{
    // Wrap the future so its waker rings the main-loop doorbell. When the
    // future pends and is later woken FROM ANY THREAD (e.g. the async-io reactor
    // for `smol::Timer`), the underlying wake both (a) marks the task runnable
    // inside the `LocalExecutor` and (b) rings the doorbell so the main loop
    // leaves its `recv()` and calls `drive_local_executor` (which `try_tick`s
    // this task on the MAIN thread). The future body is only ever polled on the
    // main thread.
    let wrapped = DoorbellFuture {
        inner: future,
        exec: Arc::clone(&LOCAL_EXECUTOR),
    };
    let task = LOCAL_EXECUTOR.exec.spawn(wrapped);
    // Ring now so the just-spawned task is drained on the next main-loop pass.
    LOCAL_EXECUTOR.ring_doorbell();
    task
}

/// Wraps a `spawn_local_inline` future so each poll installs a waker that rings
/// the main-loop doorbell in addition to the executor's own waker — bridging a
/// cross-thread wake (reactor thread) back to the main thread's `try_tick`.
struct DoorbellFuture<F> {
    inner: F,
    exec: Arc<LocalExecutorCell>,
}

impl<F: Future> Future for DoorbellFuture<F> {
    type Output = F::Output;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        // SAFETY: standard pin projection — we never move `inner` out of the
        // pinned `self`; `exec` is `Unpin` (Arc) and only read. `DoorbellFuture`
        // is structurally pinned in `inner` only.
        let this = unsafe { self.get_unchecked_mut() };
        let inner = unsafe { std::pin::Pin::new_unchecked(&mut this.inner) };
        let doorbell_waker = doorbell_waker(cx.waker().clone(), Arc::clone(&this.exec));
        let mut doorbell_cx = std::task::Context::from_waker(&doorbell_waker);
        inner.poll(&mut doorbell_cx)
    }
}

/// Build a `Waker` that delegates to `inner` and also rings `exec`'s doorbell.
fn doorbell_waker(inner: Waker, exec: Arc<LocalExecutorCell>) -> Waker {
    use std::task::{RawWaker, RawWakerVTable};

    struct DoorbellWakerData {
        inner: Waker,
        exec: Arc<LocalExecutorCell>,
    }

    unsafe fn clone(ptr: *const ()) -> RawWaker {
        let data = &*(ptr as *const DoorbellWakerData);
        let boxed = Box::new(DoorbellWakerData {
            inner: data.inner.clone(),
            exec: Arc::clone(&data.exec),
        });
        RawWaker::new(Box::into_raw(boxed) as *const (), &VTABLE)
    }
    unsafe fn wake(ptr: *const ()) {
        let data = Box::from_raw(ptr as *mut DoorbellWakerData);
        data.inner.wake_by_ref();
        data.exec.ring_doorbell();
    }
    unsafe fn wake_by_ref(ptr: *const ()) {
        let data = &*(ptr as *const DoorbellWakerData);
        data.inner.wake_by_ref();
        data.exec.ring_doorbell();
    }
    unsafe fn drop_fn(ptr: *const ()) {
        drop(Box::from_raw(ptr as *mut DoorbellWakerData));
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_fn);

    let boxed = Box::new(DoorbellWakerData { inner, exec });
    // SAFETY: the vtable functions match the `DoorbellWakerData` layout and
    // uphold the `Waker` contract (clone allocates, wake/drop free exactly
    // once). `exec`'s doorbell closure is `Send + Sync`, so ringing it from any
    // wake thread is sound; it never touches the `!Send` executor.
    unsafe { Waker::from_raw(RawWaker::new(Box::into_raw(boxed) as *const (), &VTABLE)) }
}

/// Block the current thread until the passed future completes.
pub use async_io::block_on;

pub struct SimpleExecutor {
    rx: Receiver<SpawnFunc>,
}

impl SimpleExecutor {
    pub fn new() -> Self {
        let (tx, rx) = unbounded();

        let tx_main = tx.clone();
        let tx_low = tx.clone();
        let queue_func = move |f: SpawnFunc| {
            tx_main.send(f).ok();
        };
        let queue_func_low = move |f: SpawnFunc| {
            tx_low.send(f).ok();
        };
        set_schedulers(
            Box::new(move |task| {
                queue_func(Box::new(move || {
                    task.run();
                }))
            }),
            Box::new(move |task| {
                queue_func_low(Box::new(move || {
                    task.run();
                }))
            }),
        );
        // termob fork: install the local-executor doorbell. A `spawn_local_inline`
        // task woken from any thread rings this, pushing a no-op drive marker into
        // the main channel so `tick`'s blocked `recv()` returns and drains the
        // local (`!Send`) executor on the main thread (see `drive_local_executor`).
        let tx_doorbell = tx.clone();
        set_local_doorbell(move || {
            // No-op closure: its only purpose is to unblock `recv()`. The actual
            // local-executor drive happens unconditionally in `tick()`.
            tx_doorbell.send(Box::new(|| {})).ok();
        });
        Self { rx }
    }

    pub fn tick(&self) -> anyhow::Result<()> {
        match self.rx.recv() {
            Ok(func) => func(),
            Err(err) => anyhow::bail!("while waiting for events: {:?}", err),
        };
        // Drive the `!Send` local executor on the MAIN thread after every event
        // (incl. doorbell wakes from `spawn_local_inline` futures woken on a
        // reactor thread). Polling here — never inline on the waking thread —
        // keeps `!Send` data (lua `Rc`, mux `Arc<dyn Pane>`) on the main thread.
        drive_local_executor();
        Ok(())
    }
}

pub struct ScopedExecutor {}

impl ScopedExecutor {
    pub fn new() -> Self {
        SCOPED_EXECUTOR
            .lock()
            .unwrap()
            .replace(Arc::new(Executor::new()));

        Self {}
    }

    pub async fn run<T>(&self, future: impl Future<Output = T>) -> T {
        get_scoped()
            .expect("SCOPED_EXECUTOR to be alive as long as ScopedExecutor")
            .run(future)
            .await
    }
}

impl Drop for ScopedExecutor {
    fn drop(&mut self) {
        SCOPED_EXECUTOR.lock().unwrap().take();
    }
}

#[cfg(test)]
mod local_inline_tests {
    use super::*;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// termob fork regression: a `spawn_local_inline` future that pends and is
    /// woken FROM ANOTHER THREAD must complete by being polled on the MAIN
    /// (executor) thread — not run inline on the waking thread. Holds an `Rc`
    /// (a `!Send` marker) across the cross-thread wake to mirror the lua
    /// `Rc<Lua>` case; if the future were polled off the main thread this would
    /// be UB (and `panic=abort` would abort). The test passing (future resolves
    /// on the main thread, value intact) pins the fix.
    #[test]
    fn local_inline_future_woken_cross_thread_completes_on_main_thread() {
        let executor = SimpleExecutor::new();

        // Manual cross-thread-woken future: pends once, a spawned thread flips a
        // flag and wakes it. The waker is `Send` (std `Waker`), the wake happens
        // off-thread, but the poll must occur on the main thread.
        struct CrossThreadPend {
            // `!Send` payload carried across the await point.
            marker: Rc<u32>,
            ready: Arc<AtomicBool>,
            armed: bool,
        }
        impl Future for CrossThreadPend {
            type Output = u32;
            fn poll(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<u32> {
                if self.ready.load(Ordering::Acquire) {
                    return Poll::Ready(*self.marker);
                }
                if !self.armed {
                    self.armed = true;
                    let waker = cx.waker().clone();
                    let ready = Arc::clone(&self.ready);
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(20));
                        ready.store(true, Ordering::Release);
                        waker.wake(); // cross-thread wake
                    });
                }
                Poll::Pending
            }
        }

        let result = Arc::new(std::sync::Mutex::new(None));
        let result_w = Arc::clone(&result);
        spawn_local_inline(async move {
            let v = CrossThreadPend {
                marker: Rc::new(4242),
                ready: Arc::new(AtomicBool::new(false)),
                armed: false,
            }
            .await;
            *result_w.lock().unwrap() = Some(v);
        })
        .detach();

        // Drive the main loop until the future resolves (doorbell wakes unblock
        // `recv`, `tick` drives the local executor on this thread).
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            executor.tick().expect("tick");
            if result.lock().unwrap().is_some() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "future never resolved"
            );
        }
        assert_eq!(
            *result.lock().unwrap(),
            Some(4242),
            "value intact, polled on main thread"
        );
    }
}
