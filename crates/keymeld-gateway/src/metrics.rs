use prometheus::{
    proto::MetricFamily, register_counter_vec, register_gauge_vec, register_histogram_vec,
    CounterVec, GaugeVec, HistogramVec,
};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::errors::ApiError;
use keymeld_core::identifiers::SessionId;

lazy_static::lazy_static! {
    static ref SESSION_STATE_TRANSITIONS: CounterVec = register_counter_vec!(
        "keymeld_session_state_transitions_total",
        "Total number of session state transitions",
        &["session_type", "from_state", "to_state", "success"]
    ).unwrap();

    static ref SESSION_PROCESSING_DURATION: HistogramVec = register_histogram_vec!(
        "keymeld_session_processing_duration_seconds",
        "Duration of session processing operations",
        &["session_type", "operation"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
    ).unwrap();

    static ref ACTIVE_SESSIONS: GaugeVec = register_gauge_vec!(
        "keymeld_active_sessions",
        "Number of active sessions by type and state",
        &["session_type", "state"]
    ).unwrap();

    static ref SESSION_ERRORS: CounterVec = register_counter_vec!(
        "keymeld_session_errors_total",
        "Total number of session errors",
        &["session_type", "error_type"]
    ).unwrap();

    static ref ENCLAVE_HEALTH: GaugeVec = register_gauge_vec!(
        "keymeld_enclave_health",
        "Health status of enclaves (1=healthy, 0=unhealthy)",
        &["enclave_id"]
    ).unwrap();

    static ref API_REQUESTS: CounterVec = register_counter_vec!(
        "keymeld_api_requests_total",
        "Total number of API requests",
        &["endpoint", "method", "status_code"]
    ).unwrap();

    static ref QUOTA_VIOLATIONS: CounterVec = register_counter_vec!(
        "keymeld_quota_violations_total",
        "Total number of quota violations",
        &["keygen_session_id"]
    ).unwrap();

    static ref MUSIG_OPERATIONS: CounterVec = register_counter_vec!(
        "keymeld_musig_operations_total",
        "Total number of MuSig2 operations",
        &["operation", "success"]
    ).unwrap();
}

#[derive(Clone, Debug)]
pub struct Metrics;

impl Metrics {
    pub fn record_session_state_transition(
        &self,
        session_type: &str,
        from_state: &str,
        to_state: &str,
        success: bool,
    ) {
        SESSION_STATE_TRANSITIONS
            .with_label_values(&[
                session_type,
                from_state,
                to_state,
                if success { "true" } else { "false" },
            ])
            .inc();

        info!(
            session_type = session_type,
            from_state = from_state,
            to_state = to_state,
            success = success,
            "Session state transition"
        );
    }

    pub fn record_session_processing_duration(
        &self,
        session_type: &str,
        operation: &str,
        duration: Duration,
    ) {
        SESSION_PROCESSING_DURATION
            .with_label_values(&[session_type, operation])
            .observe(duration.as_secs_f64());

        if duration.as_secs_f64() > 5.0 {
            warn!(
                session_type = session_type,
                operation = operation,
                duration_seconds = duration.as_secs_f64(),
                "Slow session processing detected"
            );
        }
    }

    pub fn update_active_session_count(&self, session_type: &str, state: &str, count: f64) {
        ACTIVE_SESSIONS
            .with_label_values(&[session_type, state])
            .set(count);
    }

    pub fn record_session_error(&self, session_type: &str, error_type: &str) {
        SESSION_ERRORS
            .with_label_values(&[session_type, error_type])
            .inc();

        error!(
            session_type = session_type,
            error_type = error_type,
            "Session error recorded"
        );
    }

    pub fn update_enclave_health(&self, enclave_id: u32, is_healthy: bool) {
        ENCLAVE_HEALTH
            .with_label_values(&[&enclave_id.to_string()])
            .set(if is_healthy { 1.0 } else { 0.0 });

        if !is_healthy {
            warn!(enclave_id = enclave_id, "Unhealthy enclave detected");
        }
    }

    pub fn record_api_request(&self, endpoint: &str, method: &str, status_code: u16) {
        API_REQUESTS
            .with_label_values(&[endpoint, method, &status_code.to_string()])
            .inc();
    }

    pub fn record_quota_violation(&self, keygen_session_id: &SessionId) {
        QUOTA_VIOLATIONS
            .with_label_values(&[&keygen_session_id.to_string()])
            .inc();

        warn!(
            keygen_session_id = %keygen_session_id,
            "Quota violation recorded"
        );
    }

    pub fn record_musig_operation(&self, operation: &str, success: bool) {
        MUSIG_OPERATIONS
            .with_label_values(&[operation, if success { "success" } else { "failure" }])
            .inc();

        if !success {
            warn!(operation = operation, "MuSig2 operation failed");
        }
    }

    pub fn export_metrics(&self) -> Result<Vec<MetricFamily>, ApiError> {
        let metric_families = prometheus::gather();
        Ok(metric_families)
    }
}

pub struct MetricsTimer {
    start: Instant,
    session_type: String,
    operation: String,
    metrics: Metrics,
}

impl MetricsTimer {
    pub fn start(metrics: Metrics, session_type: &str, operation: &str) -> Self {
        Self {
            start: Instant::now(),
            session_type: session_type.to_string(),
            operation: operation.to_string(),
            metrics,
        }
    }

    pub fn finish(self) {
        let duration = self.start.elapsed();
        self.metrics.record_session_processing_duration(
            &self.session_type,
            &self.operation,
            duration,
        );
    }
}
