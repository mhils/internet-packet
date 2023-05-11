use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(feature = "checksums")]
use internet_checksum::Checksum;

#[derive(PartialEq, Eq, Debug, Clone)]
#[repr(u8)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

impl Display for IpVersion {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            IpVersion::V4 => write!(f, "IPv4"),
            IpVersion::V6 => write!(f, "IPv6"),
        }
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Debug, Hash)]
#[repr(u8)]
pub enum TransportProtocol {
    Tcp = 0x06,
    Udp = 0x11,
}

impl Display for TransportProtocol {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            TransportProtocol::Tcp => write!(f, "TCP"),
            TransportProtocol::Udp => write!(f, "UDP"),
        }
    }
}

impl TryFrom<u8> for TransportProtocol {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x06 => Ok(TransportProtocol::Tcp),
            0x11 => Ok(TransportProtocol::Udp),
            proto => Err(ParseError::UnknownTransportProtocol(proto)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ParseError {
    UnknownTransportProtocol(u8),
    Malformed,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ParseError::UnknownTransportProtocol(proto) => {
                write!(f, "Unknown transport protocol: {proto}")
            }
            ParseError::Malformed => write!(f, "Malformed packet"),
        }
    }
}

impl std::error::Error for ParseError {}

const IPV6_EXTENSION_HEADERS: [u8; 11] = [
    0,  // Hop-by-Hop Options
    43, // Routing
    44, // Fragment
    50, // Encapsulating Security Payload
    51, // Authentication Header
    60, // Destination Options
    135, 139, 140, 253, 254,
];

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Debug, Hash)]
pub struct ConnectionId {
    pub proto: TransportProtocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl ConnectionId {
    pub fn reverse(&self) -> Self {
        ConnectionId {
            proto: self.proto,
            dst: self.src,
            src: self.dst,
        }
    }
    pub fn canonical_form(self) -> Self {
        if self.src < self.dst {
            self.reverse()
        } else {
            self
        }
    }
}

#[derive(Debug, Clone)]
pub struct InternetPacket {
    data: Vec<u8>,
    ip_version: IpVersion,
    transport_proto: TransportProtocol,
    transport_proto_offset: usize,
    payload_offset: usize,
    payload_end: usize
}

impl TryFrom<Vec<u8>> for InternetPacket {
    type Error = ParseError;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        if data.is_empty() {
            return Err(ParseError::Malformed);
        }

        let ip_version = match data[0] >> 4 {
            4 => IpVersion::V4,
            6 => IpVersion::V6,
            _ => return Err(ParseError::Malformed),
        };

        let (transport_proto, transport_proto_offset, payload_end) = match ip_version {
            IpVersion::V4 => {
                if data.len() < 20 {
                    return Err(ParseError::Malformed);
                }
                let proto = data[9];
                let offset = (data[0] & 0x0F) as usize * 4;
                let total_length = ((data[2] as usize) << 8) + data[3] as usize;
                (proto, offset, total_length)
            }
            IpVersion::V6 => {
                if data.len() < 40 {
                    return Err(ParseError::Malformed);
                }
                let mut next_header = data[6];
                let mut offset = 40;

                while IPV6_EXTENSION_HEADERS.contains(&next_header) {
                    if data.len() < offset + 8 {
                        return Err(ParseError::Malformed);
                    }
                    next_header = data[offset];
                    offset += data[offset + 1] as usize * 8 - 8;
                }

                let payload_length = ((data[4] as usize) << 8) + data[5] as usize;

                (next_header, offset, payload_length + 40)
            }
        };

        let transport_proto = match transport_proto {
            0x06 => TransportProtocol::Tcp,
            0x11 => TransportProtocol::Udp,
            _ => return Err(ParseError::UnknownTransportProtocol(transport_proto)),
        };

        let payload_offset = match transport_proto {
            TransportProtocol::Tcp => {
                let data_offset =
                    (data.get(transport_proto_offset + 12).unwrap_or(&0xff) >> 4) as usize * 4;
                transport_proto_offset + data_offset
            }
            TransportProtocol::Udp => transport_proto_offset + 8,
        };

        // We currently assume that packets are well-formed.
        if data.len() < payload_offset {
            return Err(ParseError::Malformed);
        }

        Ok(InternetPacket {
            data,
            ip_version,
            transport_proto,
            transport_proto_offset,
            payload_offset,
            payload_end,
        })
    }
}

/// A simple representation of TCP/UDP over IPv4/IPv6 packets.
impl InternetPacket {
    pub fn src_ip(&self) -> IpAddr {
        match self.ip_version {
            IpVersion::V4 => {
                let bytes: [u8; 4] = self.data[12..16].try_into().unwrap();
                IpAddr::V4(Ipv4Addr::from(bytes))
            }
            IpVersion::V6 => {
                let bytes: [u8; 16] = self.data[8..24].try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        match self.ip_version {
            IpVersion::V4 => {
                let bytes: [u8; 4] = self.data[16..20].try_into().unwrap();
                IpAddr::V4(Ipv4Addr::from(bytes))
            }
            IpVersion::V6 => {
                let bytes: [u8; 16] = self.data[24..40].try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
        }
    }

    pub fn set_src_ip(&mut self, addr: IpAddr) {
        match addr {
            IpAddr::V4(addr) => {
                assert_eq!(self.ip_version, IpVersion::V4);
                self.data[12..16].copy_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                assert_eq!(self.ip_version, IpVersion::V6);
                self.data[8..24].copy_from_slice(&addr.octets());
            }
        }
    }

    pub fn set_dst_ip(&mut self, addr: IpAddr) {
        match addr {
            IpAddr::V4(addr) => {
                assert_eq!(self.ip_version, IpVersion::V4);
                self.data[16..20].copy_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                assert_eq!(self.ip_version, IpVersion::V6);
                self.data[24..40].copy_from_slice(&addr.octets());
            }
        }
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(
            self.data[self.transport_proto_offset..self.transport_proto_offset + 2]
                .try_into()
                .unwrap(),
        )
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(
            self.data[self.transport_proto_offset + 2..self.transport_proto_offset + 4]
                .try_into()
                .unwrap(),
        )
    }

    pub fn set_src_port(&mut self, port: u16) {
        self.data[self.transport_proto_offset..self.transport_proto_offset + 2]
            .copy_from_slice(&port.to_be_bytes());
    }

    pub fn set_dst_port(&mut self, port: u16) {
        self.data[self.transport_proto_offset + 2..self.transport_proto_offset + 4]
            .copy_from_slice(&port.to_be_bytes());
    }

    pub fn src(&self) -> SocketAddr {
        SocketAddr::from((self.src_ip(), self.src_port()))
    }

    pub fn dst(&self) -> SocketAddr {
        SocketAddr::from((self.dst_ip(), self.dst_port()))
    }

    pub fn set_src(&mut self, src: &SocketAddr) {
        self.set_src_ip(src.ip());
        self.set_src_port(src.port());
    }

    pub fn set_dst(&mut self, dst: &SocketAddr) {
        self.set_dst_ip(dst.ip());
        self.set_dst_port(dst.port());
    }

    pub fn connection_id(&self) -> ConnectionId {
        ConnectionId {
            proto: self.transport_proto,
            src: self.src(),
            dst: self.dst(),
        }
    }

    pub fn inner(self) -> Vec<u8> {
        self.data
    }

    pub fn hop_limit(&self) -> u8 {
        match self.ip_version {
            IpVersion::V4 => self.data[8],
            IpVersion::V6 => self.data[7],
        }
    }

    pub fn set_hop_limit(&mut self, hop_limit: u8) {
        match self.ip_version {
            IpVersion::V4 => self.data[8] = hop_limit,
            IpVersion::V6 => self.data[7] = hop_limit,
        }
    }

    pub fn tcp_sequence_number(&self) -> u32 {
        match self.transport_proto {
            TransportProtocol::Tcp => {
                u32::from_be_bytes(
                    self.data[self.transport_proto_offset + 4..self.transport_proto_offset + 8]
                        .try_into()
                        .unwrap(),
                )
            }
            _ => 0,
        }
    }

    fn tcp_flags(&self) -> u8 {
        match self.transport_proto {
            TransportProtocol::Tcp => self.data[self.transport_proto_offset + 13],
            _ => 0,
        }
    }

    pub fn tcp_syn(&self) -> bool {
        self.tcp_flags() & 0x02 != 0
    }

    pub fn tcp_ack(&self) -> bool {
        self.tcp_flags() & 0x10 != 0
    }

    pub fn tcp_flag_str(&self) -> String {
        let mut flags: Vec<&str> = vec![];
        let flag_bits = self.tcp_flags();
        if flag_bits & 0x01 != 0 {
            flags.push("FIN");
        }
        if flag_bits & 0x02 != 0 {
            flags.push("SYN");
        }
        if flag_bits & 0x04 != 0 {
            flags.push("RST");
        }
        if flag_bits & 0x08 != 0 {
            flags.push("PSH");
        }
        if flag_bits & 0x10 != 0 {
            flags.push("ACK");
        }
        if flag_bits & 0x20 != 0 {
            flags.push("URG");
        }
        flags.join("/")
    }

    pub fn protocol(&self) -> TransportProtocol {
        self.transport_proto
    }

    pub fn payload(&self) -> &[u8] {
        &self.data[self.payload_offset..self.payload_end]
    }

    #[cfg(feature = "checksums")]
    pub fn recalculate_ip_checksum(&mut self) {
        if self.ip_version == IpVersion::V4 {
            self.data[10..12].copy_from_slice(&[0, 0]);
            let mut checksum = Checksum::new();
            checksum.add_bytes(&self.data[0..20]);
            self.data[10..12].copy_from_slice(&checksum.checksum());
        }
    }

    #[cfg(feature = "checksums")]
    fn pseudo_header_checksum(&self) -> Checksum {
        let upper_layer_packet_length = self.data.len() - self.transport_proto_offset;

        let mut checksum = Checksum::new();
        match self.ip_version {
            IpVersion::V4 => {
                let mut pseudo = [0u8; 12];
                pseudo[0..8].copy_from_slice(&self.data[12..20]);
                pseudo[9] = self.transport_proto as u8;
                pseudo[10..12].copy_from_slice(&(upper_layer_packet_length as u16).to_be_bytes());
                checksum.add_bytes(&pseudo);
            }
            IpVersion::V6 => {
                let mut pseudo = [0u8; 40];
                pseudo[0..32].copy_from_slice(&self.data[8..40]);
                pseudo[32..36].copy_from_slice(&(upper_layer_packet_length as u32).to_be_bytes());
                pseudo[39] = self.transport_proto as u8;
                checksum.add_bytes(&pseudo);
            }
        };
        checksum
    }

    #[cfg(feature = "checksums")]
    pub fn recalculate_tcp_checksum(&mut self) {
        if self.transport_proto != TransportProtocol::Tcp {
            return;
        }

        let checksum_offset = self.transport_proto_offset + 16;
        let mut checksum = self.pseudo_header_checksum();
        self.data[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);
        checksum.add_bytes(&self.data[self.transport_proto_offset..]);
        self.data[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.checksum());
    }

    #[cfg(feature = "checksums")]
    pub fn recalculate_udp_checksum(&mut self) {
        if self.transport_proto != TransportProtocol::Udp {
            return;
        }

        let checksum_offset = self.transport_proto_offset + 6;
        let mut checksum = self.pseudo_header_checksum();
        self.data[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);
        checksum.add_bytes(&self.data[self.transport_proto_offset..]);
        self.data[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.checksum());
    }
}

impl Display for ConnectionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} -> {}", self.proto, self.src, self.dst)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use data_encoding::HEXLOWER;

    use super::*;

    const TCP_SYN: &[u8] = "45000034d14b4000800680e0c0a8b2145db8d822d92100508ad94999000000008002faf01da30000020405b40103030801010402".as_bytes();
    const DNS_REQ: &[u8] =
        "60000000003c33403ffe050700000001020086fffe0580da3ffe0501481900000000000000000042\
    11040000000009070000010bbc09dd98f9b0b12e647f4454\
    095c00350024f0090006010000010000000000000669746f6a756e036f72670000ff0001".as_bytes();

    const TCP_ACK_WITH_PADDING: &[u8] = "4500002869330000320676a85db8d822c0a8b2710050d5224e95b5f3e586c974501000807d6800000000".as_bytes();

    #[test]
    fn parse_udp_ipv6_packet() {
        let mut packet = InternetPacket::try_from(HEXLOWER.decode(DNS_REQ).unwrap()).unwrap();
        assert_eq!(packet.ip_version, IpVersion::V6);
        assert_eq!(
            packet.connection_id(),
            ConnectionId {
                proto: TransportProtocol::Udp,
                src: SocketAddr::from_str("[3ffe:507:0:1:200:86ff:fe05:80da]:2396").unwrap(),
                dst: SocketAddr::from_str("[3ffe:501:4819::42]:53").unwrap(),
            }
        );
        assert_eq!(packet.hop_limit(), 64);
        assert_eq!(packet.payload().len(), 28);

        packet.set_src(&SocketAddr::from_str("[::1]:2").unwrap());
        packet.set_dst(&SocketAddr::from_str("[::3]:4").unwrap());
        assert_eq!(
            packet.connection_id(),
            ConnectionId {
                proto: TransportProtocol::Udp,
                src: SocketAddr::from_str("[::1]:2").unwrap(),
                dst: SocketAddr::from_str("[::3]:4").unwrap(),
            }
        );

        packet.set_hop_limit(42);
        assert_eq!(packet.hop_limit(), 42);
        assert_eq!(packet.tcp_flag_str(), "");
    }

    #[test]
    fn parse_udp_ipv6_packet_malformed() {
        let data = HEXLOWER.decode(DNS_REQ).unwrap();
        for i in 0..72 {
            assert!(matches!(
                InternetPacket::try_from(data[..i].to_vec()),
                Err(ParseError::Malformed)
            ));
        }
        assert!(matches!(InternetPacket::try_from(data[..72].to_vec()), Ok(_)));
    }

    #[test]
    fn parse_tcp_ipv4_packet() {
        let mut packet = InternetPacket::try_from(HEXLOWER.decode(TCP_SYN).unwrap()).unwrap();
        assert_eq!(packet.ip_version, IpVersion::V4);
        assert_eq!(
            packet.connection_id(),
            ConnectionId {
                proto: TransportProtocol::Tcp,
                src: SocketAddr::from_str("192.168.178.20:55585").unwrap(),
                dst: SocketAddr::from_str("93.184.216.34:80").unwrap(),
            }
        );
        assert_eq!(packet.hop_limit(), 128);
        assert_eq!(packet.payload(), vec![]);

        packet.set_src(&SocketAddr::from_str("1.2.3.4:5").unwrap());
        packet.set_dst(&SocketAddr::from_str("4.3.2.1:0").unwrap());
        assert_eq!(
            packet.connection_id(),
            ConnectionId {
                proto: TransportProtocol::Tcp,
                src: SocketAddr::from_str("1.2.3.4:5").unwrap(),
                dst: SocketAddr::from_str("4.3.2.1:0").unwrap(),
            }
        );

        packet.set_hop_limit(42);
        assert_eq!(packet.hop_limit(), 42);
        assert_eq!(packet.tcp_flag_str(), "SYN");

        packet.data[33] = 0xff;
        assert_eq!(packet.tcp_flag_str(), "FIN/SYN/RST/PSH/ACK/URG");
    }

    #[test]
    fn parse_tcp_ipv4_packet_malformed() {
        let data = HEXLOWER.decode(TCP_SYN).unwrap();
        for i in 0..data.len() {
            assert!(matches!(
                InternetPacket::try_from(data[..i].to_vec()),
                Err(ParseError::Malformed)
            ));
        }
    }

    #[test]
    fn parse_tcp_ipv4_packet_with_padding() {
        let packet = InternetPacket::try_from(HEXLOWER.decode(TCP_ACK_WITH_PADDING).unwrap()).unwrap();
        assert_eq!(packet.ip_version, IpVersion::V4);
        assert!(!packet.tcp_syn());
        assert!(packet.tcp_ack());
        assert_eq!(packet.payload().len(), 0);
    }

    #[cfg(feature = "checksums")]
    #[test]
    fn recalculate_ipv4_checksum() {
        let raw = HEXLOWER.decode(TCP_SYN).unwrap();
        let mut raw2 = raw.clone();
        raw2[10..12].copy_from_slice(&[0xab, 0xcd]);
        let mut packet = InternetPacket::try_from(raw2).unwrap();

        packet.recalculate_ip_checksum();
        assert_eq!(packet.data, raw);
    }

    #[cfg(feature = "checksums")]
    #[test]
    fn recalculate_tcp_checksum_ipv4() {
        let raw = HEXLOWER.decode(TCP_SYN).unwrap();
        let mut raw2 = raw.clone();
        raw2[36..38].copy_from_slice(&[0xab, 0xcd]);
        let mut packet = InternetPacket::try_from(raw2).unwrap();
        packet.recalculate_tcp_checksum();
        assert_eq!(packet.data, raw);
    }

    #[cfg(feature = "checksums")]
    #[test]
    fn recalculate_udp_checksum_ipv6() {
        let raw = HEXLOWER.decode(DNS_REQ).unwrap();
        let mut raw2 = raw.clone();
        raw2[70..72].copy_from_slice(&[0xab, 0xcd]);
        let mut packet = InternetPacket::try_from(raw2).unwrap();
        packet.recalculate_udp_checksum();
        assert_eq!(packet.data, raw);
    }

    #[test]
    fn canonicalize_connection_id() {
        let a = ConnectionId {
            proto: TransportProtocol::Tcp,
            src: SocketAddr::from_str("[::1]:2").unwrap(),
            dst: SocketAddr::from_str("[::3]:4").unwrap(),
        };
        let b = a.reverse();
        assert_ne!(a, b);
        assert_eq!(a.canonical_form(), b.canonical_form());
    }
}
