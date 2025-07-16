pub fn detect_basic_service(port: u16) -> Option<String> {
    TCP_SERVICES
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, service)| service.to_string())
}

pub fn detect_basic_udp_service(port: u16) -> Option<String> {
    UDP_SERVICES
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, service)| service.to_string())
}

pub fn is_ssl_port(port: u16) -> bool {
    // Common SSL/TLS ports
    matches!(
        port,
        443 |   // HTTPS
        465 |   // SMTPS
        587 |   // SMTP with TLS
        993 |   // IMAPS
        995 |   // POP3S
        636 |   // LDAPS
        853 |   // DNS over TLS
        990 |   // FTPS
        992 |   // Telnets
        1443 |  // HTTPS alt
        2376 |  // Docker TLS
        3269 |  // Global Catalog SSL
        5061 |  // SIP TLS
        5986 |  // WinRM HTTPS
        8443 |  // HTTPS alt
        8834 |  // Nessus HTTPS
        9443 // VMware HTTPS
    ) || {
        // Also check for common HTTPS alternative ports
        matches!(port, 8080 | 8000 | 9000 | 3000 | 4443 | 7443 | 10443)
    }
}

const TCP_SERVICES: &[(u16, &str)] = &[
    // Web Services
    (80, "http"),
    (443, "https"),
    (8080, "http-proxy"),
    (8000, "http-alt"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9000, "http-alt"),
    (3000, "http-dev"),
    // Remote Access
    (22, "ssh"),
    (23, "telnet"),
    (3389, "rdp"),
    (5900, "vnc"),
    (2222, "ssh-alt"),
    // Mail Services
    (25, "smtp"),
    (110, "pop3"),
    (143, "imap"),
    (465, "smtps"),
    (587, "submission"),
    (993, "imaps"),
    (995, "pop3s"),
    (2525, "smtp-alt"),
    // File Transfer
    (20, "ftp-data"),
    (21, "ftp"),
    (69, "tftp"),
    (990, "ftps"),
    (115, "sftp"),
    (989, "ftps-data"),
    // Databases
    (3306, "mysql"),
    (5432, "postgresql"),
    (1433, "mssql"),
    (1521, "oracle"),
    (27017, "mongodb"),
    (6379, "redis"),
    (50000, "db2"),
    (1526, "oracle-alt"),
    (27018, "mongodb-shard"),
    (27019, "mongodb-config"),
    (28017, "mongodb-web"),
    // Directory Services
    (389, "ldap"),
    (636, "ldaps"),
    (3268, "globalcatalog"),
    (3269, "globalcatalog-ssl"),
    // Network Services
    (53, "dns"),
    (123, "ntp"),
    (161, "snmp"),
    (162, "snmp-trap"),
    (67, "dhcp-server"),
    (68, "dhcp-client"),
    (179, "bgp"),
    (520, "rip"),
    (521, "ripng"),
    (853, "dns-over-tls"),
    (5353, "mdns"),
    (546, "dhcpv6-client"),
    (547, "dhcpv6-server"),
    // File Sharing
    (135, "msrpc"),
    (139, "netbios-ssn"),
    (445, "smb"),
    (2049, "nfs"),
    (548, "afp"),
    (137, "netbios-ns"),
    (138, "netbios-dgm"),
    // Security & VPN
    (500, "ipsec"),
    (1194, "openvpn"),
    (1701, "l2tp"),
    (1723, "pptp"),
    (4500, "ipsec-nat"),
    // Application Servers
    (1099, "java-rmi"),
    (8009, "ajp13"),
    (8161, "activemq"),
    (9042, "cassandra"),
    (11211, "memcached"),
    (9200, "elasticsearch"),
    (5601, "kibana"),
    (8983, "solr"),
    (9160, "cassandra-thrift"),
    (7000, "cassandra"),
    (7001, "cassandra-ssl"),
    // Development & Testing
    (4000, "node-dev"),
    (5000, "flask-dev"),
    (8000, "django-dev"),
    (9229, "node-inspector"),
    (3001, "node-dev-alt"),
    (4848, "glassfish-admin"),
    // Container & Cloud
    (2375, "docker"),
    (2376, "docker-ssl"),
    (6443, "kubernetes"),
    (10250, "kubelet"),
    (2377, "docker-swarm"),
    (4243, "docker-alt"),
    (8001, "kubernetes-api-alt"),
    (10255, "kubelet-readonly"),
    // Media & Streaming
    (554, "rtsp"),
    (1935, "rtmp"),
    (5060, "sip"),
    (5061, "sips"),
    (8554, "rtsp-alt"),
    (5004, "rtp"),
    // Monitoring & Management
    (3000, "grafana"),
    (8086, "influxdb"),
    (9090, "prometheus"),
    (8125, "statsd"),
    (8126, "statsd-admin"),
    (199, "smux"),
    (1234, "hotline"),
    (9300, "elasticsearch-cluster"),
    // Gaming
    (25565, "minecraft"),
    (27015, "steam"),
    (7777, "teamspeak"),
    (9987, "teamspeak3"),
    (28960, "cod4"),
    // Enterprise Software
    (1414, "ibm-mq"),
    (1830, "oracle-alt"),
    (5984, "couchdb"),
    (7474, "neo4j"),
    (9418, "git"),
    // Print Services
    (515, "lpr"),
    (631, "ipp"),
    (9100, "jetdirect"),
    // Proxy & Load Balancers
    (1080, "socks"),
    (3128, "squid"),
    (8118, "privoxy"),
    (9050, "tor-socks"),
    (9051, "tor-control"),
    // Backup & Sync
    (873, "rsync"),
    (6000, "x11"),
    (6001, "x11-1"),
    (6002, "x11-2"),
    (6003, "x11-3"),
    (6004, "x11-4"),
    (6005, "x11-5"),
    // IoT and Embedded
    (1883, "mqtt"),
    (8883, "mqtt-ssl"),
    (5683, "coap"),
    // Miscellaneous
    (79, "finger"),
    (113, "ident"),
    (119, "nntp"),
    (563, "nntps"),
    (1900, "upnp"),
    (2000, "cisco-sccp"),
    (11111, "vce"),
    (12345, "netbus"),
    (31337, "back-orifice"),
    (992, "telnets"),
    (513, "rlogin"),
    (514, "rsh"),
    (5901, "vnc-1"),
    (5902, "vnc-2"),
    (5903, "vnc-3"),
    (5904, "vnc-4"),
    (5905, "vnc-5"),
];

const UDP_SERVICES: &[(u16, &str)] = &[
    (53, "dns"),
    (67, "dhcp-server"),
    (68, "dhcp-client"),
    (69, "tftp"),
    (123, "ntp"),
    (137, "netbios-ns"),
    (138, "netbios-dgm"),
    (161, "snmp"),
    (162, "snmp-trap"),
    (500, "ipsec"),
    (514, "syslog"),
    (520, "rip"),
    (1194, "openvpn"),
    (1701, "l2tp"),
    (1900, "upnp"),
    (4500, "ipsec-nat"),
    (5353, "mdns"),
    (5060, "sip"),
    (6881, "bittorrent"),
    (27015, "steam"),
    (27017, "mongodb"),
    (521, "ripng"),
    (546, "dhcpv6-client"),
    (547, "dhcpv6-server"),
    (853, "dns-over-tls"),
    (1812, "radius"),
    (1813, "radius-acct"),
    (1645, "radius-alt"),
    (1646, "radius-acct-alt"),
    (2049, "nfs"),
    (111, "rpc"),
    (1434, "mssql-m"),
    (1433, "mssql"),
    (5432, "postgresql"),
    (3306, "mysql"),
    (11211, "memcached"),
    (6379, "redis"),
    (27018, "mongodb-shard"),
    (27019, "mongodb-config"),
    (28017, "mongodb-web"),
    (50000, "db2"),
    (389, "ldap"),
    (636, "ldaps"),
    (3268, "globalcatalog"),
    (3269, "globalcatalog-ssl"),
    (179, "bgp"),
    (1883, "mqtt"),
    (8883, "mqtt-ssl"),
    (5683, "coap"),
    (5004, "rtp"),
    (1935, "rtmp"),
    (8554, "rtsp-alt"),
    (873, "rsync"),
    (548, "afp"),
    (6000, "x11"),
    (631, "ipp"),
    (9100, "jetdirect"),
    (515, "lpr"),
];
