//! Shared preparation-reply admission. Charged reservations survive HTTP/task
//! cancellation until their owner drops, and retained replies keep their charge
//! until the session is released. Execution/recovery does not use this budget.
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};

const DEFAULT_LIMIT: usize = 256 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct ResponseBudget {
    limit: usize,
    used: AtomicUsize,
    rejected: AtomicU64,
}

impl Default for ResponseBudget {
    fn default() -> Self {
        Self::new(DEFAULT_LIMIT)
    }
}

impl ResponseBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
            rejected: AtomicU64::new(0),
        }
    }
    pub(crate) fn reserve(self: &Arc<Self>, bytes: usize) -> Option<ResponseCharge> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let Some(next) = used.checked_add(bytes).filter(|total| *total <= self.limit) else {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(current) => used = current,
            }
        }
        Some(ResponseCharge {
            budget: self.clone(),
            bytes,
        })
    }
    pub(crate) fn snapshot(&self) -> (usize, usize, u64) {
        (
            self.used.load(Ordering::Acquire),
            self.limit,
            self.rejected.load(Ordering::Relaxed),
        )
    }
    pub(crate) fn pressured(&self) -> bool {
        self.used.load(Ordering::Acquire) >= self.limit.saturating_sub(self.limit / 4)
    }
}

#[derive(Debug)]
pub(crate) struct ResponseCharge {
    budget: Arc<ResponseBudget>,
    bytes: usize,
}
impl ResponseCharge {
    /// Payload bounds guarantee this is at most the admission reservation.
    pub(crate) fn retain(&mut self, bytes: usize) -> bool {
        if bytes > self.bytes {
            return false;
        }
        self.budget
            .used
            .fetch_sub(self.bytes - bytes, Ordering::AcqRel);
        self.bytes = bytes;
        true
    }
}
impl Drop for ResponseCharge {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregate_reservations_refuse_overflow_and_release_on_cancel_or_retirement() {
        let budget = Arc::new(ResponseBudget::new(100));
        let mut first = budget.reserve(60).unwrap();
        assert!(budget.reserve(41).is_none());
        let second = budget.reserve(40).unwrap();
        assert!(budget.pressured());
        assert_eq!(budget.snapshot(), (100, 100, 1));
        assert!(first.retain(10));
        assert!(!first.retain(11));
        assert_eq!(budget.snapshot().0, 50);
        drop(second);
        assert!(!budget.pressured());
        drop(first);
        assert_eq!(budget.snapshot().0, 0);
        assert!(budget.reserve(usize::MAX).is_none());
    }
    #[test]
    fn concurrent_reservations_share_one_limit() {
        let budget = Arc::new(ResponseBudget::new(10));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let budget = budget.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let charge = budget.reserve(2);
                    barrier.wait();
                    assert!(budget.snapshot().0 <= 10);
                    barrier.wait();
                    drop(charge);
                });
            }
        });
        assert_eq!(budget.snapshot().0, 0);
    }
}
