//! Shared preparation-reply admission. Charged reservations survive HTTP/task
//! cancellation until their owner drops, and retained replies keep their charge
//! until their preparation executes or their session is released.
//! Execution/recovery does not use this budget.
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};

const DEFAULT_LIMIT: usize = 256 * 1024 * 1024;
/// Retained replies at or above this share of the limit, in percent, put the budget under
/// pressure, and idle keygen sessions are then released sooner (see
/// [`crate::confidential::PRESSURED_IDLE_KEYGEN`]), freeing their replies. Pending
/// reservations do not count: they drain on their own when their preparations finish or
/// are cancelled, so they never shorten an exact-retry window.
const PRESSURE_PERCENT: u128 = 75;

#[derive(Debug)]
pub(crate) struct ResponseBudget {
    limit: usize,
    /// Pending reservations plus retained replies. Admission compares this with `limit`.
    used: AtomicUsize,
    /// The part of `used` that retained replies hold.
    retained: AtomicUsize,
    rejected: AtomicU64,
}

/// One reading of a [`ResponseBudget`], for logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BudgetSnapshot {
    pub(crate) used: usize,
    pub(crate) retained: usize,
    pub(crate) limit: usize,
    pub(crate) rejected: u64,
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
            retained: AtomicUsize::new(0),
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
            retained: false,
        })
    }
    pub(crate) fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            used: self.used.load(Ordering::Acquire),
            retained: self.retained.load(Ordering::Acquire),
            limit: self.limit,
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    pub(crate) fn pressured(&self) -> bool {
        // At most `limit`, so narrowing back is lossless.
        let threshold = (self.limit as u128 * PRESSURE_PERCENT / 100) as usize;
        self.retained.load(Ordering::Acquire) >= threshold
    }
}

#[derive(Debug)]
pub(crate) struct ResponseCharge {
    budget: Arc<ResponseBudget>,
    bytes: usize,
    retained: bool,
}
impl ResponseCharge {
    /// Shrink the reservation to the reply it now retains. From here until the charge
    /// drops, its bytes count toward pressure. Callers reserve for their largest reply,
    /// which the escrow engine checks at compile time, so `bytes` never exceeds it.
    pub(crate) fn retain(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.bytes, "a reply outgrew its reservation");
        let bytes = bytes.min(self.bytes);
        let released = self.bytes - bytes;
        self.budget.used.fetch_sub(released, Ordering::AcqRel);
        if self.retained {
            self.budget.retained.fetch_sub(released, Ordering::AcqRel);
        } else {
            self.budget.retained.fetch_add(bytes, Ordering::AcqRel);
            self.retained = true;
        }
        self.bytes = bytes;
    }
}
impl Drop for ResponseCharge {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
        if self.retained {
            self.budget.retained.fetch_sub(self.bytes, Ordering::AcqRel);
        }
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
        assert_eq!(
            budget.snapshot(),
            BudgetSnapshot {
                used: 100,
                retained: 0,
                limit: 100,
                rejected: 1
            }
        );
        first.retain(10);
        assert_eq!(budget.snapshot().used, 50);
        assert_eq!(budget.snapshot().retained, 10);
        drop(second);
        drop(first);
        assert_eq!(budget.snapshot().used, 0);
        assert_eq!(budget.snapshot().retained, 0);
        assert!(budget.reserve(usize::MAX).is_none());
    }
    #[test]
    fn pending_reservations_never_pressure_the_budget_but_retained_replies_do() {
        let budget = Arc::new(ResponseBudget::new(100));
        let mut pending = budget.reserve(100).unwrap();
        assert!(
            !budget.pressured(),
            "a full budget of pending reservations drains without releasing sessions"
        );
        pending.retain(74);
        assert!(!budget.pressured());
        let mut more = budget.reserve(26).unwrap();
        assert!(!budget.pressured());
        more.retain(1);
        assert!(budget.pressured(), "75 % of the limit is retained");
        drop(pending);
        assert!(!budget.pressured());
        drop(more);
        assert_eq!(budget.snapshot().retained, 0);
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
                    assert!(budget.snapshot().used <= 10);
                    barrier.wait();
                    drop(charge);
                });
            }
        });
        assert_eq!(budget.snapshot().used, 0);
    }
}
