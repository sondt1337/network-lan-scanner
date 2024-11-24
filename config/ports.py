COMMON_PORTS =  {
            # Web Services
            80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            8000: 'HTTP-Alt', 8888: 'HTTP-Alt', 81: 'HTTP-Alt', 3000: 'Dev-HTTP',
            4443: 'HTTPS-Alt', 8081: 'HTTP-Alt', 8082: 'HTTP-Alt', 9443: 'HTTPS-Alt',
            5000: 'Flask', 5001: 'Flask-Alt', 16080: 'Alt-HTTP', 18080: 'HTTP-Testing',
            
            # Email Services
            25: 'SMTP', 465: 'SMTPS', 587: 'SMTP-SUB',
            110: 'POP3', 995: 'POP3S',
            143: 'IMAP', 993: 'IMAPS', 2525: 'SMTP-Testing', 4190: 'Sieve',
            
            # File Transfer
            20: 'FTP-DATA', 21: 'FTP', 989: 'FTPS-DATA', 990: 'FTPS',
            22: 'SSH/SFTP', 69: 'TFTP', 115: 'SFTP', 2048: 'FTP-Alt',
            2121: 'FTP-Alt2', 6666: 'IRC-FileTransfer',
            
            # Remote Access
            22: 'SSH', 23: 'TELNET', 3389: 'RDP', 5900: 'VNC',
            5901: 'VNC-1', 5902: 'VNC-2', 5903: 'VNC-3', 2222: 'SSH-Alt',
            7000: 'RDP-Alt', 32768: 'VNC-HighPort',
            
            # Database Services
            1433: 'MSSQL', 1434: 'MSSQL-UDP', 3306: 'MySQL',
            5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis',
            5984: 'CouchDB', 9200: 'Elasticsearch', 1521: 'Oracle-DB',
            27018: 'MongoDB-Alt', 50000: 'DB2', 50001: 'DB2-Alt',
            33060: 'MySQLX', 2484: 'Oracle-TNS', 49152: 'MSSQL-Alt',

            # Directory Services
            389: 'LDAP', 636: 'LDAPS', 88: 'Kerberos', 3268: 'Global-Catalog',
            3269: 'Global-Catalog-SSL', 500: 'IKE', 4500: 'IPSec-NAT',
            
            # Network Services
            53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client',
            123: 'NTP', 161: 'SNMP', 162: 'SNMP-TRAP',
            520: 'RIP', 179: 'BGP', 119: 'NNTP', 500: 'ISAKMP',
            5353: 'mDNS', 16161: 'SNMP-Alt',
            
            # File Sharing
            445: 'SMB', 139: 'NetBIOS', 137: 'NetBIOS-NS',
            138: 'NetBIOS-DGM', 2049: 'NFS', 111: 'RPC', 873: 'Rsync',
            135: 'MSRPC', 49153: 'SMB-Alt', 49154: 'SMB-Alt2',
            
            # Messaging & Communication
            5060: 'SIP', 5061: 'SIPS', 1900: 'UPNP',
            5222: 'XMPP', 5269: 'XMPP-Server', 3478: 'STUN',
            19302: 'TURN', 6667: 'IRC', 6697: 'IRC-SSL',
            
            # Media Streaming
            554: 'RTSP', 1935: 'RTMP', 8554: 'RTSP-Alt',
            7070: 'RealPlayer', 8001: 'Streaming-Alt',
            12345: 'Media-Test', 12346: 'Media-Test2',
            
            # IoT & Smart Devices
            1883: 'MQTT', 8883: 'MQTT-SSL', 5683: 'CoAP',
            5353: 'mDNS', 49152: 'UPnP', 4840: 'OPC-UA',
            
            # Development
            9000: 'Node', 4200: 'Angular', 5173: 'Vite',
            8545: 'Ethereum', 9090: 'Prometheus', 8765: 'WebSockets',
            3001: 'React-Dev', 8002: 'Custom-Dev', 1337: 'Testing',
            
            # Monitoring & Management
            161: 'SNMP', 162: 'SNMP-Trap', 10050: 'Zabbix-Agent',
            10051: 'Zabbix-Server', 8086: 'InfluxDB', 9182: 'Node-Exporter',
            9093: 'Alertmanager', 6000: 'X11', 2003: 'Graphite',
            
            # Proxy & Load Balancing
            3128: 'Squid', 8080: 'HTTP-Proxy', 9090: 'HAProxy',
            8444: 'Tomcat', 8009: 'AJP', 1080: 'SOCKS',
            
            # Game Servers
            25565: 'Minecraft', 27015: 'Source', 7777: 'Terraria',
            27005: 'Steam', 19132: 'Minecraft-Bedrock', 2302: 'Arma',
            8880: 'Unreal-Tournament',
            
            # Virtualization
            902: 'VMware', 2375: 'Docker', 2376: 'Docker-SSL',
            6443: 'Kubernetes-API', 16509: 'Libvirt', 3260: 'iSCSI',
            
            # Security
            8834: 'Nessus', 9390: 'OpenVAS', 8080: 'Webmin',
            1337: 'Metasploit', 4444: 'Payload', 2323: 'Telnet-Alt',
            
            # Misc Services
            111: 'RPC', 514: 'Syslog', 5000: 'UPnP',
            1194: 'OpenVPN', 1701: 'L2TP', 1723: 'PPTP',
            1812: 'RADIUS', 5938: 'TeamViewer', 3283: 'Apple-Remote',
            5357: 'WSDAPI', 8291: 'Mikrotik-API', 24800: 'TeamSpeak',
            26000: 'Quake', 113: 'Ident', 631: 'IPP',
            42: 'WINS', 88: 'Kerberos', 5355: 'LLMNR',
            13722: 'BackupExec', 51413: 'Transmission',
        }
