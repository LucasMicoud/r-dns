use std::str;

pub(super) fn domain_to_labels(domain: &str) -> Vec<u8> {
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

pub(super) fn labels_to_domains (labels: &Vec<u8>) -> String {
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

pub(super) fn dns_decompression(response: &Vec<u8>, query_name_start: usize) -> (usize, Vec<u8>) {
    let mut query_name:Vec<u8> = Vec::new();

    // End of labels 
    if response[query_name_start] == 0 {
        query_name.push(0);
        return (query_name_start, query_name)
    }
    // Decompression needed
    else if response[query_name_start] >> 6 == 0b11 {
        query_name.extend(dns_decompression(
            response, 
            u16::from_le_bytes([response[query_name_start + 1], response[query_name_start] & 0b0011_1111]) as usize
        ).1);
        return (query_name_start+1, query_name)
    }
    // 
    else {
        let label_length:usize = response[query_name_start] as usize;
        query_name.push(response[query_name_start]);
        query_name.extend(response[query_name_start + 1..query_name_start + 1 + label_length].to_vec());
        let (next_label_end, next_label) = dns_decompression(response, query_name_start + 1 + label_length);
        query_name.extend(next_label);
        return (next_label_end, query_name)
    }
}

pub(super) fn parse_query_type(query_type: &str) -> u16 {
    match query_type {
        "A"       => 1,
        "NS"      => 2,
        "MD"      => 3,
        "MF"      => 4,
        "CNAME"   => 5,
        "SOA"     => 6,
        "MB"      => 7,
        "MG"      => 8,
        "MR"      => 9,
        "NULL"    => 10,
        "WKS"     => 11,
        "PTR"     => 12,
        "HINFO"   => 13,
        "MINFO"   => 14,
        "MX"      => 15,
        "TXT"     => 16,
        _         => 0,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_decompression_0() {
        let no_decompression:Vec<u8> = [15, 97, 108, 116, 101, 114, 45, 115, 111, 108, 117, 116, 105, 111, 110, 115, 2, 100, 101, 0].to_vec();
        let decompressed = dns_decompression(&no_decompression, 0).1;
        assert_eq!(no_decompression, decompressed);
    }

    #[test] 
    fn test_dns_decompression_1() {
        let simple_compression:Vec<u8> = [0, 0, 0, 0, 0, 3, 44, 45, 46, 0, 0, 0, 0, 0, 0, 3, 41, 42, 43, 0b1100_0000, 5].to_vec();
        let (query_name_end, decompressed) = dns_decompression(&simple_compression, 15);
        assert_eq!(decompressed, [3, 41, 42, 43, 3, 44, 45, 46, 0].to_vec());
        assert_eq!(query_name_end, 20);
    }

    #[test]
    fn test_dns_decompression_2() {
        let google_answer: Vec<u8> = [29, 221, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 1, 40, 0, 4, 142, 250, 203, 110, 0].to_vec();
        let (query_name_end, decompressed) = dns_decompression(&google_answer, 28);
        assert_eq!(decompressed, [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0].to_vec());
        assert_eq!(query_name_end, 29);
    }

    #[test]
    fn test_dns_decompression_3() {
        let multiple_decompressions = [3, 41,42,43, 0,0,0,0,0,0, 3, 44, 45, 46, 0b1100_0000, 0, 0,0,0,0, 3, 47, 48, 49, 0b1100_0000, 10, 0,0,0,0, 0b1100_0000, 20].to_vec();
        println!("{}", multiple_decompressions[20]);
        let (query_name_end, decompressed) = dns_decompression(&multiple_decompressions, 30);
        assert_eq!(decompressed, [3, 47, 48, 49, 3, 44, 45, 46, 3, 41, 42, 43, 0].to_vec());
        assert_eq!(query_name_end, 31);
    }
}