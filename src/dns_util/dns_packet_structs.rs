use std::fmt;

use crate::dns_util::packet_factory::labels_to_domains;


#[derive(Debug)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSAnswer>
}

pub struct DNSHeader {
    //// Unique ID of the transaction. Query and response should have the same.
    pub query_id: u16,
    /// Set of flags
    /// --> [0]      Query. 0 for query, 1 for response
    /// --> [1-4]    Operation code. Kind of message. 0 for query
    /// --> [5]      Authoritative answer. Only for response. 1 if responding 
    ///              server is an authority for the domain, 0 otherwise
    /// --> [6]      Truncation. 1 if message truncated, 0 otherwise
    /// --> [7]      Recursion desired. Should be set to 1 in query
    /// --> [8]      Reursion available. For response
    /// --> [9-11]   Reserved. Set to 0
    /// --> [12-15]  Response code. Set to 0 in query. In response:
    ///                  0 = no error
    ///                  1 = format error
    ///                  2 = server failure
    ///                  3 = name error (do not exist)
    ///                  4 = not implemented
    ///                  5 = refused
    pub flags: u16,
    /// Number of question in the query
    pub questions_count: u16,
    /// Number of records in the answers section. Set to 0x00 in query
    pub answers_count: u16,
    /// Number of records in the authority section. Set to 0x00 in query
    pub authority_count: u16,
    /// Number of records in the additionnal section. Set to 0x00 in query
    pub additional_count: u16,
}

impl fmt::Debug for DNSHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match writeln!(f, "query_id: {}", self.query_id){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "flags:"){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "\tquery: {:b}", self.flags >> 15 & 1){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "\toperation code: {}", self.flags >> 11 & 0b0111_1){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "\tauthoritative answer: {}", self.flags >> 10 & 0b0000_01){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "\ttruncation: {}", self.flags >> 9 & 0b0000_001){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "\trecursion desired: {}", self.flags >> 8 & 0b0000_0001){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "\trecursion available: {}", self.flags >> 7 & 0b0000_0000_1){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "\treserved: {}", self.flags >> 4 & 0b0000_0000_0111){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "\tresponse code: {}", self.flags & 0b0000_0000_0000_1111){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "questions count: {}", self.questions_count){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "answer count: {}", self.answers_count){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "authority count: {}", self.authority_count){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        writeln!(f, "additional count: {}", self.additional_count)
    }
}
pub struct DNSQuestion {
    /// Set of labels preceeded by their length. Ends with \x00.
    /// news.google.com will give \x04news\x06google\x03com\x00.
    pub query_name: Vec<u8>,
    /// Type of resource queried
    /// --> 1 = A       - a host address
    /// --> 2 = NS      - an authoritative name server
    /// --> 3 = MD      - a mail destination (Obsolete - use MX)
    /// --> 4 = MF      - a mail forwarder (Obsolete - use MX)
    /// --> 5 = CNAME   - the canonical name for an alias
    /// --> 6 = SOA     - marks the start of a zone of authority
    /// --> 7 = MB      - a mailbox domain name (EXPERIMENTAL)
    /// --> 8 = MG      - a mail group member (EXPERIMENTAL)
    /// --> 9 = MR      - a mail rename domain name (EXPERIMENTAL)
    /// --> 10 = NULL   - a null RR (EXPERIMENTAL)
    /// --> 11 = WKS    - a well known service description
    /// --> 12 = PTR    - a domain name pointer
    /// --> 13 = HINFO  - host information
    /// --> 14 = MINFO  - mailbox or mail list information
    /// --> 15 = MX     - mail exchange
    /// --> 16 = text   - text strings
    pub query_type: u16,
    /// Class fo query. Set to 0x01 for Internet.
    pub query_class: u16,
}

impl fmt::Debug for DNSQuestion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match writeln!(f, "querry_name: {}", labels_to_domains(&self.query_name)){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        match writeln!(f, "querry_type: {:?}", self.query_type){
            Err(e) => println!("{:?}", e),
            _ => ()
        };
        writeln!(f, "querry_class: {:?}", self.query_class)
    }
}

pub struct DNSAnswer {

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

impl fmt::Debug for DNSAnswer {
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
        writeln!(f, "querry: {:?}", self.rdata)
    }
}
