use log::warn;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::{tcp::TcpPacket, Packet};

const CRYPTOJACKING_PORTS: &[u16] = &[3333, 4444, 5555, 9009];
const CRYPTOJACKING_PAYLOAD: &[u8] = &[0x41, 0x41, 0x41];


trait IpPacketInfo {
    fn get_source(&self) -> String;
    fn get_destination(&self) -> String;
}

impl IpPacketInfo for Ipv4Packet<'_> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }
}

impl IpPacketInfo for Ipv6Packet<'_> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }
}

fn capture_packets(interface: NetworkInterface) {
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Error creating channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet_data = packet.to_vec();
                analyze_packet(&packet_data);
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
                break;
            }
        }
    }
}

fn analyze_packet(packet_data: &[u8]) {
    if let Some(ethernet) = EthernetPacket::new(packet_data) {
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                    analyze_ipv4_packet(&ipv4_packet);
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6_packet) = Ipv6Packet::new(ethernet.payload()) {
                    analyze_ipv6_packet(&ipv6_packet);
                }
            }
            _ => {}
        }
    }
}

fn analyze_ipv4_packet(ipv4_packet: &Ipv4Packet) {
    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                analyze_tcp_packet(ipv4_packet, &tcp_packet);
            }
        }
        _ => {}
    }
}

fn analyze_ipv6_packet(ipv6_packet: &Ipv6Packet) {
    match ipv6_packet.get_next_header() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                analyze_tcp_packet(ipv6_packet, &tcp_packet);
            }
        }
        _ => {}
    }
}

fn analyze_tcp_packet(ip_packet: &dyn IpPacketInfo, tcp_packet: &TcpPacket) {
    let source_port = tcp_packet.get_source();
    let destination_port = tcp_packet.get_destination();
    let flags = tcp_packet.get_flags();

    // Check for specific ports commonly used in cryptojacking
    if CRYPTOJACKING_PORTS.contains(&source_port) || CRYPTOJACKING_PORTS.contains(&destination_port) {
        let source_ip = ip_packet.get_source();
        let destination_ip = ip_packet.get_destination();

        // Check for specific flag combinations associated with cryptojacking
        if (flags & TcpFlags::SYN) == TcpFlags::SYN && (flags & TcpFlags::ACK) != TcpFlags::ACK {
            warn!(
                "Potential cryptojacking detected! Source IP: {}, Destination IP: {}",
                source_ip, destination_ip
            );
        }

        // Check for specific data patterns in payload associated with cryptojacking
        let payload = tcp_packet.payload();
        if payload
            .windows(CRYPTOJACKING_PAYLOAD.len())
            .any(|window| window == CRYPTOJACKING_PAYLOAD)
        {
            warn!(
                "Potential cryptojacking detected! Source IP: {}, Destination IP: {}",
                source_ip, destination_ip
            );
        }

        // Warning message outside if conditions
        warn!(
            "Potential cryptojacking detected! Source IP: {}, Destination IP: {}",
            source_ip, destination_ip
        );
    }
}



fn main() {
    // Obtain the network interface for packet capturing
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .next()
        .expect("No network interface found.");

    // Capture network packets and perform analysis
    capture_packets(interface);
}