use std::fmt;
use rand::Rng;
pub struct DNSHeader {
    //// Unique ID of the transaction. Query and response should have the same.
    pub query_id: u16,
    /// Set of flags
    /// --> [0]      Query. 0 for query, 1 for response
    /// --> [1-4]    Operation code. Kind of message. 0 for query
    /// --> [5]      Authoritative answer. Only for response. 1 if responding 
    ///              server is an authority for the domain, 0 otherwise
    /// --> [6]      Truncation. 1 if message truncated, 0 otherwise
    /// --> [7]      Recursion desired. Should be 1 in query
    /// --> [8]      Reursion available. For response, should be 0 in query.
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

impl DNSHeader {
    pub fn create_query_header(questions_count: u16) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            query_id: rng.gen::<u16>(),
            flags: 0b0000_0001_0000_0000,
            questions_count: questions_count,
            answers_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn parse_header_from_response(response: &Vec<u8>) -> Self {
        Self {
            query_id: u16::from_le_bytes([response[1], response[0]]),
            flags: u16::from_le_bytes([response[3], response[2]]),
            questions_count: u16::from_le_bytes([response[5], response[4]]),  
            answers_count: u16::from_le_bytes([response[7], response[6]]),
            authority_count: u16::from_le_bytes([response[9], response[8]]),
            additional_count: u16::from_le_bytes([response[11], response[10]]),
        }
    }

    pub fn prepare(&self) -> Vec<u8> {
        let mut prepared_header: Vec<u8> = Vec::new();

        prepared_header.extend([
            self.query_id.to_le_bytes()[1],
            self.query_id.to_le_bytes()[0]
        ]);
        prepared_header.extend([
            self.flags.to_le_bytes()[1],
            self.flags.to_le_bytes()[0]
        ]);
        prepared_header.extend([
            self.questions_count.to_le_bytes()[1],
            self.questions_count.to_le_bytes()[0]
        ]);
        prepared_header.extend([
            self.answers_count.to_le_bytes()[1],
            self.answers_count.to_le_bytes()[0]
        ]);
        prepared_header.extend([
            self.authority_count.to_le_bytes()[1],
            self.authority_count.to_le_bytes()[0]
        ]);
        prepared_header.extend([
            self.additional_count.to_le_bytes()[1],
            self.additional_count.to_le_bytes()[0]
        ]);

        prepared_header
    }
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