//! Track only allocations on the waiting caller's thread. The caller source is
//! allocated before tracking; waiting must not allocate its own upload copy.
#[allow(dead_code)] // Shared fixture includes the native acceptance helpers.
mod binary_support;
use binary_support::Fixture;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use yamora::{BinaryClient, BinaryOptions, CancellationToken, ErrorKind};
struct Observed;
thread_local! {static WATCH:Cell<bool>=const {Cell::new(false)};}
static LARGE: AtomicUsize = AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: Observed = Observed;
fn observe(size: usize) {
    if size >= 1024 * 1024 && WATCH.try_with(Cell::get).unwrap_or(false) {
        LARGE.fetch_add(1, Ordering::Relaxed);
    }
}
unsafe impl GlobalAlloc for Observed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe(size);
        unsafe { System.realloc(pointer, layout, size) }
    }
}
#[test]
fn waiting_call_does_not_freeze_source_or_reach_network() {
    let f = Fixture::new("hostile");
    let mut config = f.config();
    config.max_concurrent_calls = 1;
    let c = Arc::new(BinaryClient::new(config).unwrap());
    let first = c.clone();
    let admitted = thread::spawn(move || {
        first
            .put("c", "gate-owner", b"value: 1\n", BinaryOptions::default())
            .unwrap()
    });
    f.wait_count("dispatch", 1);
    let mut source = b"value: 2\n# ".to_vec();
    source.resize(16 * 1024 * 1024, b'x');
    let token = CancellationToken::new();
    let cancel = token.clone();
    let waiting = c.clone();
    let waiter = thread::spawn(move || {
        WATCH.set(true);
        let result = waiting.put(
            "c",
            "never",
            &source,
            BinaryOptions {
                cancellation: Some(&token),
                ..Default::default()
            },
        );
        WATCH.set(false);
        result.unwrap_err()
    });
    thread::sleep(Duration::from_millis(80));
    cancel.cancel();
    let error = waiter.join().unwrap();
    std::fs::write(f.root.join("release"), b"release").unwrap();
    admitted.join().unwrap();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert!(!error.may_have_committed());
    assert_eq!(
        LARGE.load(Ordering::Relaxed),
        0,
        "WAITER_MUST_NOT_COPY_SOURCE"
    );
    assert_eq!(f.count("connections"), 1);
}
