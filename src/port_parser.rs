use std::collections::HashSet;

pub fn parse_ports(port_str: &str) -> Result<Vec<u16>, String> {
    let mut ports = HashSet::new();

    for part in port_str.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                return Err(format!("Invalid port range: {}", part));
            }

            let start: u16 = range[0]
                .parse()
                .map_err(|_| format!("Invalid port: {}", range[0]))?;
            let end: u16 = range[1]
                .parse()
                .map_err(|_| format!("Invalid port: {}", range[1]))?;

            if start > end {
                return Err(format!(
                    "Start port is greater than end port: {}-{}",
                    start, end
                ));
            }

            for port in start..=end {
                ports.insert(port);
            }
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port: {}", part))?;
            ports.insert(port);
        }
    }

    let mut sorted_ports: Vec<u16> = ports.into_iter().collect();
    sorted_ports.sort();
    Ok(sorted_ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_port() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
    }

    #[test]
    fn test_port_range() {
        assert_eq!(parse_ports("80-82").unwrap(), vec![80, 81, 82]);
    }

    #[test]
    fn test_mixed_ports() {
        assert_eq!(
            parse_ports("80,443,22-24").unwrap(),
            vec![22, 23, 24, 80, 443]
        );
    }
}
