use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Prometheus-compatible latency histogram buckets in milliseconds
/// These buckets are designed to capture P50, P95, P99 percentiles for network operations
pub const LATENCY_HISTOGRAM_BUCKETS: [f64; 15] = [
    0.5,           // 500 microseconds
    1.0,           // 1ms
    2.5,           // 2.5ms
    5.0,           // 5ms
    10.0,          // 10ms
    25.0,          // 25ms
    50.0,          // 50ms
    100.0,         // 100ms
    250.0,         // 250ms
    500.0,         // 500ms
    1000.0,        // 1s
    2500.0,        // 2.5s
    5000.0,        // 5s
    10000.0,       // 10s
    f64::INFINITY, // catch-all
];

#[derive(Debug)]
pub struct RequestRateTracker {
    requests_current_minute: AtomicU32,
    requests_previous_minute: AtomicU32,
    current_minute: AtomicU64,
}

impl RequestRateTracker {
    pub fn new() -> Self {
        let current_minute = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60;

        Self {
            requests_current_minute: AtomicU32::new(0),
            requests_previous_minute: AtomicU32::new(0),
            current_minute: AtomicU64::new(current_minute),
        }
    }

    pub fn record_request(&self) {
        let now_minute = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60;

        let current_minute = self.current_minute.load(Ordering::Acquire);

        if now_minute > current_minute {
            // Rotate to new minute
            let old_current = self.requests_current_minute.swap(1, Ordering::AcqRel);
            self.requests_previous_minute
                .store(old_current, Ordering::Release);
            self.current_minute.store(now_minute, Ordering::Release);
        } else {
            // Increment current minute
            self.requests_current_minute.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub fn requests_per_minute(&self) -> f64 {
        let now_minute = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60;

        let current_minute = self.current_minute.load(Ordering::Acquire);

        if now_minute > current_minute {
            // We're in a new minute, use previous minute's data
            self.requests_previous_minute.load(Ordering::Acquire) as f64
        } else {
            // Still in current minute, use current data
            self.requests_current_minute.load(Ordering::Acquire) as f64
        }
    }

    pub fn current_count(&self) -> u32 {
        self.requests_current_minute.load(Ordering::Acquire)
    }
}

impl Default for RequestRateTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Prometheus-compatible histogram tracker for latency percentiles
/// This tracks latency buckets that allow calculation of P95, P99, etc.
#[derive(Debug)]
pub struct LatencyHistogramTracker {
    // Current window buckets (counts for each histogram bucket)
    current_buckets: Mutex<Vec<u64>>,
    current_total_count: AtomicU64,
    current_total_sum: AtomicU64,

    // Previous window buckets (for stable metrics during rotation)
    previous_buckets: Mutex<Vec<u64>>,
    previous_total_count: AtomicU64,
    previous_total_sum: AtomicU64,

    current_minute: AtomicU64,
}

impl LatencyHistogramTracker {
    pub fn new() -> Self {
        let current_minute = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60;

        let bucket_count = LATENCY_HISTOGRAM_BUCKETS.len();

        Self {
            current_buckets: Mutex::new(vec![0u64; bucket_count]),
            current_total_count: AtomicU64::new(0),
            current_total_sum: AtomicU64::new(0),
            previous_buckets: Mutex::new(vec![0u64; bucket_count]),
            previous_total_count: AtomicU64::new(0),
            previous_total_sum: AtomicU64::new(0),
            current_minute: AtomicU64::new(current_minute),
        }
    }

    pub fn record_latency(&self, latency_ms: f64) {
        let now_minute = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60;

        let current_minute = self.current_minute.load(Ordering::Acquire);

        if now_minute > current_minute {
            self.rotate_window();
        }

        // Find the appropriate bucket for this latency
        let bucket_index = LATENCY_HISTOGRAM_BUCKETS
            .iter()
            .position(|&bucket| latency_ms <= bucket)
            .unwrap_or(LATENCY_HISTOGRAM_BUCKETS.len() - 1);

        // Update current window
        if let Ok(mut buckets) = self.current_buckets.lock() {
            buckets[bucket_index] += 1;
        }
        self.current_total_count.fetch_add(1, Ordering::Relaxed);
        self.current_total_sum
            .fetch_add(latency_ms as u64, Ordering::Relaxed);
    }

    fn rotate_window(&self) {
        let now_minute = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60;

        // Move current to previous
        if let (Ok(mut current), Ok(mut previous)) =
            (self.current_buckets.lock(), self.previous_buckets.lock())
        {
            std::mem::swap(&mut *current, &mut *previous);
            current.fill(0); // Reset current buckets
        }

        let current_count = self.current_total_count.swap(0, Ordering::AcqRel);
        let current_sum = self.current_total_sum.swap(0, Ordering::AcqRel);
        self.previous_total_count
            .store(current_count, Ordering::Release);
        self.previous_total_sum
            .store(current_sum, Ordering::Release);

        self.current_minute.store(now_minute, Ordering::Release);
    }

    /// Get histogram data for Prometheus export
    pub fn get_histogram_data(&self) -> HistogramData {
        let now_minute = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60;

        let current_minute = self.current_minute.load(Ordering::Acquire);

        let (buckets, total_count, total_sum) = if now_minute > current_minute {
            // Use previous minute's data for stable metrics
            let buckets = self.previous_buckets.lock().unwrap().clone();
            let count = self.previous_total_count.load(Ordering::Acquire);
            let sum = self.previous_total_sum.load(Ordering::Acquire);
            (buckets, count, sum)
        } else {
            // Use current minute's data
            let buckets = self.current_buckets.lock().unwrap().clone();
            let count = self.current_total_count.load(Ordering::Acquire);
            let sum = self.current_total_sum.load(Ordering::Acquire);
            (buckets, count, sum)
        };

        HistogramData {
            buckets: LATENCY_HISTOGRAM_BUCKETS.to_vec(),
            bucket_counts: buckets,
            total_count,
            total_sum,
        }
    }
}

impl Default for LatencyHistogramTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Prometheus-compatible histogram data
#[derive(Debug, Clone)]
pub struct HistogramData {
    pub buckets: Vec<f64>,
    pub bucket_counts: Vec<u64>,
    pub total_count: u64,
    pub total_sum: u64,
}

/// Combined metrics tracker that provides Prometheus-compatible metrics
#[derive(Debug)]
pub struct MetricsTracker {
    successful_requests: RequestRateTracker,
    failed_requests: RequestRateTracker,
    latency_histogram: LatencyHistogramTracker,
}

impl MetricsTracker {
    pub fn new() -> Self {
        Self {
            successful_requests: RequestRateTracker::new(),
            failed_requests: RequestRateTracker::new(),
            latency_histogram: LatencyHistogramTracker::new(),
        }
    }

    /// Record a successfully completed request with latency
    pub fn record_successful_request(&self, latency: std::time::Duration) {
        let latency_ms = latency.as_secs_f64() * 1000.0;
        self.successful_requests.record_request();
        self.latency_histogram.record_latency(latency_ms);
    }

    /// Record a failed request (network error, timeout, serialization error, etc.)
    pub fn record_failed_request(&self) {
        self.failed_requests.record_request();
    }

    /// Record a request completion with latency (backwards compatibility)
    pub fn record_request_completed(&self, latency_ms: f64) {
        self.successful_requests.record_request();
        self.latency_histogram.record_latency(latency_ms);
    }

    /// Get current failure rate as a percentage for the current time window (0.0 to 100.0)
    pub fn failure_rate(&self) -> f64 {
        let successful = self.successful_requests.requests_per_minute();
        let failed = self.failed_requests.requests_per_minute();
        let total = successful + failed;

        if total > 0.0 {
            (failed / total) * 100.0
        } else {
            0.0
        }
    }

    /// Get current window request counts (successful, failed)
    pub fn current_window_counts(&self) -> (u32, u32) {
        (
            self.successful_requests.current_count(),
            self.failed_requests.current_count(),
        )
    }

    pub fn get_metrics(&self) -> ConnectionMetrics {
        let successful = self.successful_requests.requests_per_minute();
        let failed = self.failed_requests.requests_per_minute();
        ConnectionMetrics {
            requests_per_minute: successful + failed,
            successful_requests_per_minute: successful,
            failed_requests_per_minute: failed,
            requests_in_current_window: self.successful_requests.current_count()
                + self.failed_requests.current_count(),
            latency_histogram: self.latency_histogram.get_histogram_data(),
            failure_rate: self.failure_rate(),
        }
    }
}

impl Default for MetricsTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Error classification for better metrics tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestErrorType {
    /// Network-level error (connection lost, timeout, etc.)
    Network,
    /// Serialization/deserialization error
    Serialization,
    /// Protocol error (invalid message format, etc.)
    Protocol,
    /// Application-level error (command processing failed)
    Application,
    /// Request timeout
    Timeout,
}

#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    pub requests_per_minute: f64,
    pub successful_requests_per_minute: f64,
    pub failed_requests_per_minute: f64,
    pub requests_in_current_window: u32,
    pub latency_histogram: HistogramData,
    pub failure_rate: f64,
}

impl ConnectionMetrics {
    /// Check if the connection appears healthy based on recent metrics
    pub fn is_healthy(&self) -> bool {
        // Connection is healthy if failure rate is below 50%
        // If no requests in current window, assume healthy
        if self.requests_in_current_window == 0 {
            return true;
        }
        self.failure_rate < 50.0
    }
}
