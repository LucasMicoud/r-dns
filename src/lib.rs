pub mod dns_util;

use std::net::UdpSocket;
use std::time::Duration;
use rand::{self, Rng};

pub use crate::dns_util::dns_packet_structures::{
    dns_header::DNSHeader,
    dns_resource_record::DNSResourceRecord,
    dns_question::DNSQuestion,
    dns_packet::DNSPacket
};

pub fn resolve_ipv4(domain: &str) -> (u8, u8, u8, u8) {
    let response = make_dns_request(domain, "A", "1.1.1.1");
    println!("{:?}", response);
    (0,0,0,0)
}

pub fn make_dns_request(domain: &str, query_type: &str, dns_server: &str) -> DNSPacket {
    let mut rng = rand::thread_rng();
    
    let packet = DNSPacket::create_query_packet(vec![domain], query_type);
    let socket = UdpSocket::bind(("0.0.0.0", rng.gen_range(1024..65535)))
        .expect("couldn't bind to address");

    let _ = socket.set_write_timeout(Some(Duration::new(5, 0)));
    let _ = socket.set_read_timeout(Some(Duration::new(5, 0)));
    
    socket.send_to(&packet.prepare(), (dns_server, 53))
        .expect("Could not send");

    let mut buf: [u8; 1232] = [0; 1232];

    socket.recv_from(&mut buf)
        .expect("Could not receive");
    println!("{:?}", buf);
    DNSPacket::parse_response(buf.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        resolve_ipv4("google.com");
    }
}
