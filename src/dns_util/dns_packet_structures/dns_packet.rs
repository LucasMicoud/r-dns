use super::{
    dns_header::DNSHeader,
    dns_question::DNSQuestion,
    dns_resource_record::DNSResourceRecord,
    util::parse_query_type
};

impl DNSPacket {
    pub fn create_query_packet(domains: Vec<&str>, query_type: &str) -> Self {
        let mut questions: Vec<DNSQuestion> = Vec::new();
        for domain in &domains {
            questions.push(DNSQuestion::create_question(domain, parse_query_type(query_type)));
        };
        DNSPacket {
            header: DNSHeader::create_query_header(domains.len() as u16),
            questions: questions,
            resource_records: Vec::new(),
        }
    }

    pub fn parse_response(response: Vec<u8>) -> Self {
        let header = DNSHeader::parse_header_from_response(&response);
        let mut current_start: usize = 12; // header length
        let mut questions: Vec<DNSQuestion> = Vec::new();
        for _i in 0..header.questions_count {
            let (parsed_length, question) = DNSQuestion::parse_question_from_response(&response, current_start);
            current_start += parsed_length;
            questions.push(question);
        };
        let mut answers: Vec<DNSResourceRecord> = Vec::new();
        for _i in 0..header.answers_count {
            let (parsed_length, answer) = DNSResourceRecord::parse_rr_from_response(&response, current_start);
            current_start += parsed_length;
            answers.push(answer);
        };
        Self {
            header: header,
            questions: questions,
            resource_records: answers
        }
    }

    pub fn prepare(&self) -> Vec<u8> {
        let mut prepared_packet: Vec<u8> = Vec::new();

        prepared_packet.append(&mut self.header.prepare());
    
        for question in &self.questions {
            prepared_packet.append(&mut question.prepare());
        };
        for answer in &self.resource_records {
            prepared_packet.append(&mut answer.prepare());
        };

        prepared_packet
    }
}

#[derive(Debug)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub resource_records: Vec<DNSResourceRecord>
}