use std::fmt;

use crate::dns_util::dns_packet_structures::util::labels_to_domains;

use super::util::domain_to_labels;

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
    /// --> 16 = TXT   - text strings
    pub query_type: u16,
    /// Class fo query. Set to 0x01 for Internet.
    pub query_class: u16,
}

impl DNSQuestion {
    pub fn create_question(domain: &str, query_type: u16) -> Self {
        Self {
            query_name: domain_to_labels(domain),
            query_type: query_type,
            query_class: 1,
        }
    }

    pub fn parse_question_from_response(response: &Vec<u8>, question_start: usize) -> (usize, Self) {
        let query_name_end = question_start + response[question_start..].iter().position(|&r| r == 0).unwrap();
        (query_name_end - question_start + 5, Self {
            query_name: response[question_start..query_name_end+1].to_vec(),
            query_type: u16::from_le_bytes([response[query_name_end + 2], response[query_name_end + 1]]),
            query_class: u16::from_le_bytes([response[query_name_end + 4], response[query_name_end + 3]]),
        })
    }

    pub fn prepare(&self) -> Vec<u8> {
        let mut prepared_question: Vec<u8> = Vec::new();
        prepared_question.extend(&self.query_name);
        prepared_question.extend([
            self.query_type.to_le_bytes()[1],
            self.query_type.to_le_bytes()[0]
        ]);
        prepared_question.extend([
            self.query_class.to_le_bytes()[1],
            self.query_class.to_le_bytes()[0]
        ]);
        prepared_question
    }
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