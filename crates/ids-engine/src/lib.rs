//! Detection primitives for RustGuard.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::{Duration, Instant},
};

/// Thresholds and resource limits for passive TCP port-scan detection.
#[derive(Clone, Debug)]
pub struct PortScanConfig {
    pub window: Duration,
    pub unique_ports: usize,
    pub unique_hosts: usize,
    pub cooldown: Duration,
    pub max_sources: usize,
    pub max_targets_per_source: usize,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            unique_ports: 12,
            unique_hosts: 12,
            cooldown: Duration::from_secs(300),
            max_sources: 10_000,
            max_targets_per_source: 2_048,
        }
    }
}

/// A single observed TCP SYN connection attempt.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SynObservation {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub destination_port: u16,
}

/// Classification attached to a detected scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanType {
    Vertical,
    Horizontal,
    Mixed,
}

/// Detection result emitted when a source crosses a configured threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortScanAlert {
    pub source: IpAddr,
    pub last_destination: IpAddr,
    pub last_destination_port: u16,
    pub scan_type: ScanType,
    pub unique_ports: usize,
    pub unique_hosts: usize,
    pub unique_targets: usize,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Target {
    destination: IpAddr,
    port: u16,
}

#[derive(Debug)]
struct SourceActivity {
    targets: HashMap<Target, Instant>,
    last_seen: Instant,
    last_alert: Option<Instant>,
}

/// Sliding-window detector for vertical and horizontal TCP scans.
///
/// Only TCP SYN observations should be passed to this detector. Repeated SYNs
/// to the same destination/port pair count once in the active window. Per-source
/// target and global source limits bound memory use.
pub struct PortScanDetector {
    config: PortScanConfig,
    sources: HashMap<IpAddr, SourceActivity>,
}

impl PortScanDetector {
    /// Create a detector with the provided thresholds and resource limits.
    pub fn new(config: PortScanConfig) -> Self {
        Self {
            config: PortScanConfig {
                window: config.window.max(Duration::from_secs(1)),
                unique_ports: config.unique_ports.max(1),
                unique_hosts: config.unique_hosts.max(1),
                cooldown: config.cooldown,
                max_sources: config.max_sources.max(1),
                max_targets_per_source: config.max_targets_per_source.max(1),
            },
            sources: HashMap::new(),
        }
    }

    /// Observe one TCP SYN and return a scan alert when a threshold is crossed.
    pub fn observe(&mut self, observation: SynObservation, now: Instant) -> Option<PortScanAlert> {
        self.sources.retain(|_, activity| {
            now.saturating_duration_since(activity.last_seen) <= self.config.window
        });

        if !self.sources.contains_key(&observation.source)
            && self.sources.len() >= self.config.max_sources
        {
            if let Some(oldest_source) = self
                .sources
                .iter()
                .min_by_key(|(_, activity)| activity.last_seen)
                .map(|(source, _)| *source)
            {
                self.sources.remove(&oldest_source);
            }
        }

        let activity = self
            .sources
            .entry(observation.source)
            .or_insert_with(|| SourceActivity {
                targets: HashMap::new(),
                last_seen: now,
                last_alert: None,
            });
        activity.last_seen = now;
        activity.targets.retain(|_, observed_at| {
            now.saturating_duration_since(*observed_at) <= self.config.window
        });

        let target = Target {
            destination: observation.destination,
            port: observation.destination_port,
        };
        if !activity.targets.contains_key(&target)
            && activity.targets.len() >= self.config.max_targets_per_source
        {
            if let Some(oldest_target) = activity
                .targets
                .iter()
                .min_by_key(|(_, observed_at)| **observed_at)
                .map(|(target, _)| *target)
            {
                activity.targets.remove(&oldest_target);
            }
        }
        activity.targets.insert(target, now);

        let unique_ports = activity
            .targets
            .keys()
            .map(|target| target.port)
            .collect::<HashSet<_>>()
            .len();
        let unique_hosts = activity
            .targets
            .keys()
            .map(|target| target.destination)
            .collect::<HashSet<_>>()
            .len();
        let vertical = unique_ports >= self.config.unique_ports;
        let horizontal = unique_hosts >= self.config.unique_hosts;
        let scan_type = match (vertical, horizontal) {
            (true, true) => ScanType::Mixed,
            (true, false) => ScanType::Vertical,
            (false, true) => ScanType::Horizontal,
            (false, false) => return None,
        };

        if activity.last_alert.is_some_and(|last_alert| {
            now.saturating_duration_since(last_alert) < self.config.cooldown
        }) {
            return None;
        }
        activity.last_alert = Some(now);

        Some(PortScanAlert {
            source: observation.source,
            last_destination: observation.destination,
            last_destination_port: observation.destination_port,
            scan_type,
            unique_ports,
            unique_hosts,
            unique_targets: activity.targets.len(),
        })
    }

    /// Number of sources currently tracked (useful for monitoring and tests).
    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn config() -> PortScanConfig {
        PortScanConfig {
            window: Duration::from_secs(30),
            unique_ports: 4,
            unique_hosts: 4,
            cooldown: Duration::from_secs(60),
            max_sources: 2,
            max_targets_per_source: 16,
        }
    }

    #[test]
    fn detects_vertical_scan_after_distinct_ports() {
        let start = Instant::now();
        let mut detector = PortScanDetector::new(config());
        let mut result = None;
        for port in 1..=4 {
            result = detector.observe(
                SynObservation {
                    source: ip(1),
                    destination: ip(2),
                    destination_port: port,
                },
                start + Duration::from_secs(port as u64),
            );
        }
        let alert = result.expect("threshold should emit an alert");
        assert_eq!(alert.scan_type, ScanType::Vertical);
        assert_eq!(alert.unique_ports, 4);
        assert_eq!(alert.unique_hosts, 1);
    }

    #[test]
    fn detects_horizontal_scan_across_hosts() {
        let start = Instant::now();
        let mut detector = PortScanDetector::new(config());
        let mut result = None;
        for host in 2..=5 {
            result = detector.observe(
                SynObservation {
                    source: ip(1),
                    destination: ip(host),
                    destination_port: 443,
                },
                start + Duration::from_secs(host as u64),
            );
        }
        let alert = result.expect("threshold should emit an alert");
        assert_eq!(alert.scan_type, ScanType::Horizontal);
        assert_eq!(alert.unique_ports, 1);
        assert_eq!(alert.unique_hosts, 4);
    }

    #[test]
    fn duplicate_targets_do_not_inflate_scan_counts() {
        let start = Instant::now();
        let mut detector = PortScanDetector::new(config());
        for _ in 0..20 {
            assert!(detector
                .observe(
                    SynObservation {
                        source: ip(1),
                        destination: ip(2),
                        destination_port: 22
                    },
                    start,
                )
                .is_none());
        }
    }

    #[test]
    fn cooldown_suppresses_repeat_alerts() {
        let start = Instant::now();
        let mut detector = PortScanDetector::new(config());
        for port in 1..=4 {
            detector.observe(
                SynObservation {
                    source: ip(1),
                    destination: ip(2),
                    destination_port: port,
                },
                start + Duration::from_secs(port as u64),
            );
        }
        let during_cooldown = detector.observe(
            SynObservation {
                source: ip(1),
                destination: ip(2),
                destination_port: 5,
            },
            start + Duration::from_secs(10),
        );
        assert!(during_cooldown.is_none());
        let mut after_cooldown = None;
        for port in 6..=9 {
            after_cooldown = detector.observe(
                SynObservation {
                    source: ip(1),
                    destination: ip(2),
                    destination_port: port,
                },
                start + Duration::from_secs(70 + port as u64),
            );
        }
        assert!(after_cooldown.is_some());
    }

    #[test]
    fn sliding_window_expires_old_targets_and_bounds_sources() {
        let start = Instant::now();
        let mut detector = PortScanDetector::new(config());
        for port in 1..=3 {
            detector.observe(
                SynObservation {
                    source: ip(1),
                    destination: ip(2),
                    destination_port: port,
                },
                start,
            );
        }
        detector.observe(
            SynObservation {
                source: ip(3),
                destination: ip(4),
                destination_port: 80,
            },
            start + Duration::from_secs(1),
        );
        detector.observe(
            SynObservation {
                source: ip(5),
                destination: ip(6),
                destination_port: 80,
            },
            start + Duration::from_secs(2),
        );
        assert_eq!(detector.tracked_sources(), 2);

        let mut scan_alert = None;
        for port in 10..=13 {
            scan_alert = detector.observe(
                SynObservation {
                    source: ip(1),
                    destination: ip(2),
                    destination_port: port,
                },
                start + Duration::from_secs(40),
            );
        }
        assert!(scan_alert.is_some());
    }

    #[test]
    fn bounded_state_property_holds_for_many_observations() {
        let start = Instant::now();
        let mut detector = PortScanDetector::new(config());
        let mut seed = 7_u64;
        for index in 0..10_000_u64 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let source = (seed % 20 + 1) as u8;
            let destination = ((seed >> 8) % 250 + 1) as u8;
            let port = ((seed >> 16) % u16::MAX as u64 + 1) as u16;
            let elapsed = Duration::from_millis(index * 2);
            detector.observe(
                SynObservation {
                    source: ip(source),
                    destination: ip(destination),
                    destination_port: port,
                },
                start + elapsed,
            );
            assert!(detector.sources.len() <= 2);
            assert!(detector
                .sources
                .values()
                .all(|activity| activity.targets.len() <= 16));
        }
    }
}
