use std::fmt;

use crate::dns_util::dns_packet_structures::util::dns_decompression;

use super::util::labels_to_domains;

pub struct DNSResourceRecord {
    /// Name queried, in the same format as in DNSQuestion
    pub query_name: Vec<u8>,
    /// Same as in DNSQuestion
    pub query_type: u16,
    /// Same as in DNSQuestion
    pub query_class: u16,
    /// Time to store the record in cache. Can possibly be 0 or negative
    pub record_ttl: i32,
    /// Length of the rdata field
    pub rdata_length: u16,
    /// Actual data received from the answer. Specific content depends on the 
    /// query type
    pub rdata: Vec<u8>,
}

impl DNSResourceRecord {
    pub fn parse_rr_from_response (response: &Vec<u8>, answer_start:usize) -> (usize, Self) {
        let (query_name_end, query_name) = dns_decompression(response, answer_start);
        let rdata_length = u16::from_le_bytes([response[query_name_end + 10], response[query_name_end + 9]]);
        (query_name_end - answer_start + 11 + rdata_length as usize, Self {
            query_name: query_name,
            query_type: u16::from_le_bytes([response[query_name_end + 2], response[query_name_end + 1]]),
            query_class: u16::from_le_bytes([response[query_name_end + 4], response[query_name_end + 3]]),
            record_ttl: i32::from_le_bytes([response[query_name_end + 6], response[query_name_end + 5], response[query_name_end + 8], response[query_name_end + 7]]),
            rdata_length: rdata_length,
            rdata: response[query_name_end + 11..query_name_end + 11 + rdata_length as usize].to_vec(),
        })
    }

    pub fn prepare (&self) -> Vec<u8> {
        let mut prepared_rr: Vec<u8> = Vec::new();
        
        prepared_rr.extend(&self.query_name);
        prepared_rr.extend([
            self.query_type.to_le_bytes()[1],
            self.query_type.to_le_bytes()[0]
        ]);
        prepared_rr.extend([
            self.query_class.to_le_bytes()[1],
            self.query_class.to_le_bytes()[0]
        ]);
        prepared_rr.extend([
            self.record_ttl.to_le_bytes()[1],
            self.record_ttl.to_le_bytes()[0],
            self.record_ttl.to_le_bytes()[3],
            self.record_ttl.to_le_bytes()[2]
        ]);
        prepared_rr.extend([
            self.rdata_length.to_le_bytes()[1],
            self.rdata_length.to_le_bytes()[0]
        ]);
        prepared_rr.extend(&self.rdata);

        prepared_rr
    }
}

impl fmt::Debug for DNSResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match writeln!(f, "querry name: {}", labels_to_domains(&self.query_name)){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "querry type: {}", self.query_type){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "querry class: {}", self.query_class){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "querry type: {}", self.query_type){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "rdata length: {}", self.rdata_length){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        writeln!(f, "rdata: {:?}", self.rdata)
    }
}
