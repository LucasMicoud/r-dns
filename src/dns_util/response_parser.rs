use crate::{DNSAnswer, DNSHeader, DNSQuestion};

use super::dns_packet_structs::DNSPacket;

pub fn parse_response(response: Vec<u8>) -> DNSPacket {
    println!("{:?}", response);
    let header = parse_header(&response);
    println!("{:?}", header);
    let mut current_start: usize = 12; // header length
    let mut questions: Vec<DNSQuestion> = Vec::new();
    for _i in 0..header.questions_count {
        let (parsed_length, question) = parse_question(&response, current_start);
        current_start += parsed_length;
        questions.push(question);
    };
    let mut answers: Vec<DNSAnswer> = Vec::new();
    for _i in 0..header.answers_count {
        let (parsed_length, answer) = parse_answer(&response, current_start);
        current_start += parsed_length;
        answers.push(answer);
    };
    DNSPacket {
        header: header,
        questions: questions,
        answers: answers
    }
}

fn parse_header(response: &Vec<u8>) -> DNSHeader {
    DNSHeader {
        query_id: u16::from_le_bytes([response[1], response[0]]),
        flags: u16::from_le_bytes([response[3], response[2]]),
        questions_count: u16::from_le_bytes([response[5], response[4]]),  
        answers_count: u16::from_le_bytes([response[7], response[6]]),
        authority_count: u16::from_le_bytes([response[9], response[8]]),
        additional_count: u16::from_le_bytes([response[11], response[10]]),
    }
}

fn parse_question(response: &Vec<u8>, question_start: usize) -> (usize, DNSQuestion) {
    let query_name_end = question_start + response[question_start..].iter().position(|&r| r == 0).unwrap();
    (query_name_end - question_start + 5, DNSQuestion {
        query_name: response[question_start..query_name_end+1].to_vec(),
        query_type: u16::from_le_bytes([response[query_name_end + 2], response[query_name_end + 1]]),
        query_class: u16::from_le_bytes([response[query_name_end + 4], response[query_name_end + 3]]),
    })
}

fn parse_answer(response: &Vec<u8>, answer_start: usize) -> (usize, DNSAnswer) {
    println!("{answer_start}");
    let (query_name_end, query_name) = dns_decompression(response, answer_start);
    println!("{:?}", query_name);
    let rdata_length = u16::from_le_bytes([response[query_name_end + 10], response[query_name_end + 9]]);
    (query_name_end - answer_start + 10 + rdata_length as usize, DNSAnswer {
        query_name: query_name,
        query_type: u16::from_le_bytes([response[query_name_end + 2], response[query_name_end + 1]]),
        query_class: u16::from_le_bytes([response[query_name_end + 4], response[query_name_end + 3]]),
        record_ttl: i32::from_le_bytes([response[query_name_end + 6], response[query_name_end + 5], response[query_name_end + 8], response[query_name_end + 7]]),
        rdata_length: rdata_length,
        rdata: response[query_name_end + 11..query_name_end + 11 + rdata_length as usize].to_vec(),
    })
}

fn dns_decompression(response: &Vec<u8>, query_name_start: usize) -> (usize, Vec<u8>) {
    let mut query_name:Vec<u8> = Vec::new();
    
    println!("DNS DECOMPRESSION : {} --- {} - {:x} - {:b} - {:b}", query_name_start, response[query_name_start], response[query_name_start], response[query_name_start] >> 6, response[query_name_start]);

    if response[query_name_start] == 0 {
        query_name.push(0);
        return (query_name_start, query_name)
    }
    else if response[query_name_start] >> 6 == 0b11 {
        query_name.extend(dns_decompression(
            response, 
            u16::from_le_bytes([response[query_name_start + 1], response[query_name_start] & 0b0011_1111, ]) as usize
        ).1);
        return (query_name_start+1, query_name)
    }
    else {
        let label_length:usize = response[query_name_start] as usize;
        query_name.push(response[query_name_start]);
        query_name.extend(response[query_name_start + 1..query_name_start + 1 + label_length].to_vec());
        query_name.extend(dns_decompression(response, query_name_start + 1 + label_length).1);
        return (query_name_start, query_name)
    }
}