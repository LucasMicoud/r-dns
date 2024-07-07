use crate::{DNSHeader, DNSQuestion};
use rand::Rng;
use std::str;

use super::dns_packet_structs::DNSPacket;

fn create_header(questions_count: u16) -> DNSHeader {
    let mut rng = rand::thread_rng();

    let header = DNSHeader {
        query_id: rng.gen::<u16>(),
        flags: 0b0000_0001_0000_0000,
        questions_count: questions_count,
        answers_count: 0,
        authority_count: 0,
        additional_count: 0,
    };
    header
}

fn create_question(domain: &str) -> DNSQuestion {
    let question = DNSQuestion {
        query_name: domain_to_labels(domain),
        query_type: 1,
        query_class: 1,
    };
    question
}

fn domain_to_labels(domain: &str) -> Vec<u8> {
    let mut labels: Vec<u8> = Vec::new();
    let mut counters: Vec<u8> = Vec::new();

    let mut counter: u8 = 0;
    // compute the lengths of the parts of the domain
    for (_i, elem) in domain.as_bytes().iter().enumerate() {
        if *elem == 46 {
            counters.push(counter);
            counter += 1;
        }
        else {
            counter += 1;
        }
    }
    // Adds the parts of the domain to the vector
    let mut previous_position = 0;
    for (_i, elem) in counters.iter().enumerate() {
        labels.push(*elem - previous_position);
        labels.extend(domain[previous_position as usize..(*elem) as usize].as_bytes());
        previous_position = *elem + 1;
    }
    // Pushes the last part of the domain
    labels.push(domain.len() as u8 - previous_position);
    labels.extend(domain[previous_position as usize..].as_bytes());
    labels.push(0);
    labels
}

pub fn labels_to_domains (labels: &Vec<u8>) -> String {
    let mut current_position = 0;
    let mut domain:String = "".to_string();
    while current_position < labels.len() - 1 { // -1 because of the last null byte
        let new_domain_part: &str = match str::from_utf8(&labels[current_position+1..current_position + (labels[current_position] as usize) + 1]) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        domain += new_domain_part;
        current_position += (labels[current_position] + 1) as usize;
        if labels[current_position] != 0 { domain += "."; }
    }
    domain
}

pub fn create_packet(domains: Vec<&str>) -> DNSPacket {
    let header = create_header(domains.len() as u16);
    let mut questions: Vec<DNSQuestion> = Vec::new();
    for domain in domains{
        questions.push(create_question(domain));
    }
    DNSPacket { header: header, questions: questions, answers: Vec::new() }
}

pub fn prepare_packet(packet: DNSPacket) -> Vec<u8> {

    let mut prepared_packet: Vec<u8> = Vec::new();

    prepared_packet.extend([
        packet.header.query_id.to_le_bytes()[1],
        packet.header.query_id.to_le_bytes()[0]
    ]);
    prepared_packet.extend([
        packet.header.flags.to_le_bytes()[1],
        packet.header.flags.to_le_bytes()[0]
    ]);
    prepared_packet.extend([
        packet.header.questions_count.to_le_bytes()[1],
        packet.header.questions_count.to_le_bytes()[0]
    ]);
    prepared_packet.extend([
        packet.header.answers_count.to_le_bytes()[1],
        packet.header.answers_count.to_le_bytes()[0]
    ]);
    prepared_packet.extend([
        packet.header.authority_count.to_le_bytes()[1],
        packet.header.authority_count.to_le_bytes()[0]
    ]);
    prepared_packet.extend([
        packet.header.additional_count.to_le_bytes()[1],
        packet.header.additional_count.to_le_bytes()[0]
    ]);

    for question in packet.questions {
        prepared_packet.extend(question.query_name);
        prepared_packet.extend([
            question.query_type.to_le_bytes()[1],
            question.query_type.to_le_bytes()[0]
        ]);
        prepared_packet.extend([
            question.query_class.to_le_bytes()[1],
            question.query_class.to_le_bytes()[0]
        ]);
    }

    prepared_packet
}

