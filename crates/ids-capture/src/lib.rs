//! Passive packet capture and network-layer parsing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ids_engine::SynObservation;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

/// Capture interface name and optional system description.
#[derive(Clone, Debug)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
}

/// List capture interfaces visible to libpcap/Npcap.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, String> {
    #[cfg(feature = "live-capture")]
    {
        pcap::Device::list()
            .map(|devices| {
                devices
                    .into_iter()
                    .map(|device| InterfaceInfo {
                        name: device.name,
                        description: device.desc,
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "live-capture"))]
    {
        Err("interface listing is disabled; rebuild with --features ids-cli/live-capture".into())
    }
}

/// Extract a TCP SYN attempt from an Ethernet frame.
///
/// Supports Ethernet with up to two VLAN tags, IPv4, and IPv6 with common
/// extension headers. Fragmented non-initial packets, malformed frames, and
/// TCP packets with ACK set are ignored.
pub fn parse_tcp_syn(frame: &[u8]) -> Option<SynObservation> {
    if frame.len() < 14 {
        return None;
    }

    let mut ethertype = read_u16(frame, 12)?;
    let mut network_offset = 14;
    let mut vlan_depth = 0;
    while matches!(ethertype, ETHERTYPE_VLAN | ETHERTYPE_QINQ) {
        if vlan_depth >= 2 {
            return None;
        }
        ethertype = read_u16(frame, network_offset + 2)?;
        network_offset += 4;
        vlan_depth += 1;
    }

    let (source, destination, transport_offset) = match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(frame, network_offset)?,
        ETHERTYPE_IPV6 => parse_ipv6(frame, network_offset)?,
        _ => return None,
    };

    if frame.get(transport_offset + 13).is_none() {
        return None;
    }
    let flags = frame[transport_offset + 13];
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None;
    }

    Some(SynObservation {
        source,
        destination,
        destination_port: read_u16(frame, transport_offset + 2)?,
    })
}

fn parse_ipv4(frame: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, usize)> {
    let header = frame.get(offset..offset.checked_add(20)?)?;
    if header[0] >> 4 != 4 || header[9] != 6 {
        return None;
    }
    let header_len = usize::from(header[0] & 0x0f) * 4;
    if header_len < 20 || frame.get(offset..offset.checked_add(header_len)?).is_none() {
        return None;
    }
    let fragment_offset = u16::from_be_bytes([header[6], header[7]]) & 0x1fff;
    if fragment_offset != 0 {
        return None;
    }
    let source = IpAddr::V4(Ipv4Addr::new(
        header[12], header[13], header[14], header[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        header[16], header[17], header[18], header[19],
    ));
    Some((source, destination, offset + header_len))
}

fn parse_ipv6(frame: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, usize)> {
    let header = frame.get(offset..offset.checked_add(40)?)?;
    if header[0] >> 4 != 6 {
        return None;
    }
    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&header[8..24]).ok()?));
    let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&header[24..40]).ok()?));
    let mut next_header = header[6];
    let mut transport_offset = offset + 40;

    // Bound extension-header traversal so malformed chains cannot consume
    // unbounded CPU. Eight headers is well above ordinary network stacks.
    for _ in 0..8 {
        match next_header {
            6 => return Some((source, destination, transport_offset)),
            0 | 43 | 60 => {
                let extension = frame.get(transport_offset..transport_offset.checked_add(2)?)?;
                let length = (usize::from(extension[1]) + 1) * 8;
                next_header = extension[0];
                frame.get(transport_offset..transport_offset.checked_add(length)?)?;
                transport_offset += length;
            }
            44 => {
                let extension = frame.get(transport_offset..transport_offset.checked_add(8)?)?;
                let fragment_offset = u16::from_be_bytes([extension[2], extension[3]]) & 0xfff8;
                if fragment_offset != 0 {
                    return None;
                }
                next_header = extension[0];
                transport_offset += 8;
            }
            51 => {
                let extension = frame.get(transport_offset..transport_offset.checked_add(2)?)?;
                let length = (usize::from(extension[1]) + 2) * 4;
                next_header = extension[0];
                frame.get(transport_offset..transport_offset.checked_add(length)?)?;
                transport_offset += length;
            }
            _ => return None,
        }
    }
    None
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset.checked_add(1)?)?,
    ]))
}

/// Capture TCP packets from one selected interface and call `on_syn` for each
/// observed initial SYN. Requires the `live-capture` feature and libpcap or
/// Npcap installed on the host.
pub fn capture_interface<R, F>(interface: &str, on_ready: R, mut on_syn: F) -> Result<(), String>
where
    R: FnOnce(),
    F: FnMut(SynObservation),
{
    #[cfg(feature = "live-capture")]
    {
        capture_with_pcap(interface, on_ready, &mut on_syn).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "live-capture"))]
    {
        let _ = (interface, on_ready, &mut on_syn);
        Err("live capture is disabled; rebuild with --features ids-cli/live-capture".into())
    }
}

#[cfg(feature = "live-capture")]
fn capture_with_pcap<R, F>(interface: &str, on_ready: R, on_syn: &mut F) -> Result<(), pcap::Error>
where
    R: FnOnce(),
    F: FnMut(SynObservation),
{
    use pcap::{Capture, Device, Error};

    let mut capture = Capture::from_device(Device::from(interface))?
        .promisc(true)
        .snaplen(256)
        .timeout(500)
        .open()?;
    if capture.get_datalink() != pcap::Linktype::ETHERNET {
        return Err(Error::InvalidLinktype);
    }
    capture.filter("tcp", true)?;
    on_ready();
    tracing_capture_started(interface);

    loop {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some(observation) = parse_tcp_syn(packet.data) {
                    on_syn(observation);
                }
            }
            Err(Error::TimeoutExpired) => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(feature = "live-capture")]
fn tracing_capture_started(interface: &str) {
    eprintln!("RustGuard passive packet capture active on {interface}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_syn_frame(flags: u8) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 20 + 20];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame[14] = 0x45;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[192, 0, 2, 10]);
        frame[30..34].copy_from_slice(&[198, 51, 100, 20]);
        frame[34..36].copy_from_slice(&12345_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&443_u16.to_be_bytes());
        frame[47] = flags;
        frame
    }

    #[test]
    fn parses_ipv4_syn_but_ignores_ack_and_malformed_frames() {
        let parsed = parse_tcp_syn(&ipv4_syn_frame(0x02)).expect("SYN should be parsed");
        assert_eq!(parsed.source.to_string(), "192.0.2.10");
        assert_eq!(parsed.destination.to_string(), "198.51.100.20");
        assert_eq!(parsed.destination_port, 443);
        assert!(parse_tcp_syn(&ipv4_syn_frame(0x12)).is_none());
        assert!(parse_tcp_syn(&[0; 10]).is_none());
    }

    #[test]
    fn parses_single_vlan_tag() {
        let frame = ipv4_syn_frame(0x02);
        let mut vlan_frame = Vec::with_capacity(frame.len() + 4);
        vlan_frame.extend_from_slice(&frame[..12]);
        vlan_frame.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        vlan_frame.extend_from_slice(&[0, 1]);
        vlan_frame.extend_from_slice(&frame[12..]);
        assert_eq!(parse_tcp_syn(&vlan_frame).unwrap().destination_port, 443);
    }

    #[test]
    fn rejects_non_initial_ipv4_fragments() {
        let mut frame = ipv4_syn_frame(0x02);
        frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
        assert!(parse_tcp_syn(&frame).is_none());
    }
}
