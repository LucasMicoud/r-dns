pub mod dns_util;

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;
use dns_util::packet_factory::create_packet;
use rand;

pub use crate::dns_util::dns_packet_structs::{ DNSHeader, DNSAnswer, DNSQuestion };
pub use crate::dns_util::packet_factory::prepare_packet;
pub use crate::dns_util::response_parser::parse_response;

pub fn init_socket(dns_server: Ipv4Addr) -> std::io::Result<UdpSocket> {
    UdpSocket::bind((dns_server, 53))
}

pub fn dns_query(dns_server: Ipv4Addr, domain: &str) {
    
    let _rng = rand::thread_rng();
    
    let socket = UdpSocket::bind("0.0.0.0:34568")
        .expect("couldn't bind to address");
    let _ = socket.set_write_timeout(Some(Duration::new(5, 0)));
    let _ = socket.set_read_timeout(Some(Duration::new(5, 0)));
    let packet = create_packet(vec![domain]);
    let prepared_packet = prepare_packet(packet);
    socket.send_to(&prepared_packet, (dns_server, 53)).expect("Could not send");
    let mut buf: [u8; 1024] = [0; 1024];

    socket.recv_from(&mut buf).expect("Could not receive");

    let packet = parse_response(buf.to_vec());
    println!("{:#?}", packet);
    for answer in packet.answers { println!("{:#?}", answer)}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        dns_query( Ipv4Addr::new(8,8,8,8), "google.com");
    }
}
