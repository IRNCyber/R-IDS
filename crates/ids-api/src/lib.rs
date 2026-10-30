//! Local HTTP API and live port-scan detection service.

use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use ids_engine::{PortScanAlert, PortScanConfig, ScanType};
#[cfg(feature = "live-capture")]
use ids_engine::{PortScanDetector, SynObservation};
use serde::{Deserialize, Serialize};
#[cfg(feature = "live-capture")]
use std::{thread, time::Instant};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;

static NEXT_ALERT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct AppState {
    alerts: Arc<RwLock<Vec<Alert>>>,
    capture: Arc<RwLock<CaptureStatus>>,
    packets_analyzed: Arc<AtomicU64>,
    packets_per_second: Arc<AtomicU64>,
}

/// Alert record returned by the API and consumed by the dashboard.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub source: String,
    pub destination: String,
    pub port: String,
    pub rule: String,
    pub time: String,
    pub age: u64,
    pub status: AlertStatus,
    pub description: String,
    pub protocol: String,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum AlertStatus {
    New,
    Acknowledged,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AlertQuery {
    pub severity: Option<Severity>,
    pub q: Option<String>,
    pub status: Option<AlertStatus>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatus {
    pub state: CaptureState,
    pub interface: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Idle,
    Starting,
    Capturing,
    Error,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub total_alerts: usize,
    pub new_alerts: usize,
    pub critical_and_high: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub packets_analyzed: u64,
    pub packets_per_second: u64,
    pub sensors_online: usize,
    pub sensors_total: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub status: &'static str,
    pub capture: CaptureStatus,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlert {
    pub status: AlertStatus,
}

/// Create an API router with an empty alert feed and idle capture state.
pub fn router() -> Router {
    router_with_state(new_state())
}

fn new_state() -> AppState {
    AppState {
        alerts: Arc::new(RwLock::new(Vec::new())),
        capture: Arc::new(RwLock::new(CaptureStatus {
            state: CaptureState::Idle,
            interface: None,
            error: None,
        })),
        packets_analyzed: Arc::new(AtomicU64::new(0)),
        packets_per_second: Arc::new(AtomicU64::new(0)),
    }
}

fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/sources", get(capture_status))
        .route("/api/v1/stats/overview", get(overview))
        .route("/api/v1/alerts", get(list_alerts))
        .route("/api/v1/alerts/{id}", get(get_alert).patch(update_alert))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// Start the API and optionally monitor a packet-capture interface.
pub async fn serve(
    address: SocketAddr,
    interface: Option<String>,
    detection_config: PortScanConfig,
) -> io::Result<()> {
    let state = new_state();
    if let Some(interface) = interface {
        {
            let mut capture = state.capture.write().await;
            capture.interface = Some(interface.clone());
            capture.state = CaptureState::Starting;
        }
        #[cfg(feature = "live-capture")]
        start_capture(state.clone(), interface, detection_config)?;
        #[cfg(not(feature = "live-capture"))]
        {
            let _ = detection_config;
            let mut capture = state.capture.write().await;
            capture.state = CaptureState::Error;
            capture.error = Some(
                "Live capture is disabled; rebuild with --features ids-cli/live-capture".into(),
            );
        }
    }
    let app = router_with_state(state);
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "RustGuard API listening");
    axum::serve(listener, app).await
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: "ok",
        capture: state.capture.read().await.clone(),
    })
}

async fn capture_status(State(state): State<AppState>) -> Json<CaptureStatus> {
    Json(state.capture.read().await.clone())
}

async fn list_alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertQuery>,
) -> Json<Vec<Alert>> {
    let alerts = state.alerts.read().await;
    let filtered = alerts
        .iter()
        .filter(|alert| {
            query
                .severity
                .map_or(true, |severity| alert.severity == severity)
        })
        .filter(|alert| query.status.map_or(true, |status| alert.status == status))
        .filter(|alert| {
            query.q.as_ref().map_or(true, |term| {
                let term = term.to_lowercase();
                format!(
                    "{} {} {} {} {}",
                    alert.title, alert.source, alert.destination, alert.id, alert.rule
                )
                .to_lowercase()
                .contains(&term)
            })
        })
        .cloned()
        .collect();
    Json(filtered)
}

async fn get_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Alert>, StatusCode> {
    state
        .alerts
        .read()
        .await
        .iter()
        .find(|alert| alert.id == id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn update_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(update): Json<UpdateAlert>,
) -> Result<Json<Alert>, StatusCode> {
    let mut alerts = state.alerts.write().await;
    let Some(alert) = alerts.iter_mut().find(|alert| alert.id == id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    alert.status = update.status;
    Ok(Json(alert.clone()))
}

async fn overview(State(state): State<AppState>) -> Json<Overview> {
    let alerts = state.alerts.read().await;
    let capture = state.capture.read().await;
    let critical = alerts
        .iter()
        .filter(|a| a.severity == Severity::Critical)
        .count();
    let high = alerts
        .iter()
        .filter(|a| a.severity == Severity::High)
        .count();
    let medium = alerts
        .iter()
        .filter(|a| a.severity == Severity::Medium)
        .count();
    let low = alerts
        .iter()
        .filter(|a| a.severity == Severity::Low)
        .count();
    Json(Overview {
        total_alerts: alerts.len(),
        new_alerts: alerts
            .iter()
            .filter(|a| a.status == AlertStatus::New)
            .count(),
        critical_and_high: critical + high,
        critical,
        high,
        medium,
        low,
        packets_analyzed: state.packets_analyzed.load(Ordering::Relaxed),
        packets_per_second: state.packets_per_second.load(Ordering::Relaxed),
        sensors_online: usize::from(capture.state == CaptureState::Capturing),
        sensors_total: usize::from(capture.interface.is_some()),
    })
}

fn create_scan_alert(scan: PortScanAlert, window: Duration) -> Alert {
    let scan_name = match scan.scan_type {
        ScanType::Vertical => "TCP port scan",
        ScanType::Horizontal => "TCP host sweep",
        ScanType::Mixed => "TCP mixed port scan",
    };
    Alert {
        id: format!("RG-LIVE-{:010}", NEXT_ALERT_ID.fetch_add(1, Ordering::Relaxed)),
        title: format!("{scan_name} detected"),
        severity: Severity::High,
        source: scan.source.to_string(),
        destination: scan.last_destination.to_string(),
        port: scan.last_destination_port.to_string(),
        rule: "RG-TCP-SCAN-001".into(),
        time: current_utc_time(),
        age: 0,
        status: AlertStatus::New,
        description: format!(
            "Observed {} unique destination ports across {} hosts ({} unique targets) in {} seconds.",
            scan.unique_ports,
            scan.unique_hosts,
            scan.unique_targets,
            window.as_secs()
        ),
        protocol: "TCP".into(),
        count: scan.unique_targets as u64,
    }
}

fn current_utc_time() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() % 86_400);
    format!(
        "{:02}:{:02}:{:02} UTC",
        seconds / 3_600,
        seconds / 60 % 60,
        seconds % 60
    )
}

#[cfg(feature = "live-capture")]
fn start_capture(state: AppState, interface: String, config: PortScanConfig) -> io::Result<()> {
    thread::Builder::new()
        .name("rustguard-packet-capture".into())
        .spawn(move || {
            let capture_state = state.clone();
            let mut detector = PortScanDetector::new(config.clone());
            let mut rate_window = Instant::now();
            let mut packets_in_window = 0_u64;
            let result = ids_capture::capture_interface(
                &interface,
                || {
                    let mut capture = capture_state.capture.blocking_write();
                    capture.state = CaptureState::Capturing;
                    capture.error = None;
                },
                |observation: SynObservation| {
                    state.packets_analyzed.fetch_add(1, Ordering::Relaxed);
                    packets_in_window += 1;
                    let now = Instant::now();
                    if now.duration_since(rate_window) >= Duration::from_secs(1) {
                        state
                            .packets_per_second
                            .store(packets_in_window, Ordering::Relaxed);
                        packets_in_window = 0;
                        rate_window = now;
                    }
                    if let Some(scan) = detector.observe(observation, now) {
                        let alert = create_scan_alert(scan, config.window);
                        state.alerts.blocking_write().push(alert);
                    }
                },
            );
            if let Err(error) = result {
                let mut capture = state.capture.blocking_write();
                capture.state = CaptureState::Error;
                capture.error = Some(error);
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ids_engine::ScanType;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn live_alert_describes_vertical_and_horizontal_scan_counts() {
        let alert = create_scan_alert(
            PortScanAlert {
                source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
                last_destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
                last_destination_port: 443,
                scan_type: ScanType::Vertical,
                unique_ports: 12,
                unique_hosts: 1,
                unique_targets: 12,
            },
            Duration::from_secs(60),
        );
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.status, AlertStatus::New);
        assert!(alert.title.contains("port scan"));
        assert!(alert.description.contains("12 unique destination ports"));
    }
}
