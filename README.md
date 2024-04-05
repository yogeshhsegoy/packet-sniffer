# Network Packet Analyzer

This Python script analyzes network packets and extracts information such as HTTP, HTTPS, FTP, SMTP, DNS, and ARP data. It can filter packets based on protocols and IP addresses.

## Usage

1. **Installation**

   - Ensure you have Python 3 installed on your system.
   - Clone the repository or download the `network_analyzer.py` file.

2. **Running the Script**

   - Open a terminal and navigate to the directory containing `network_analyzer.py`.
   - Run the script with `sudo` privileges to capture raw packets:

     ```bash
     sudo python3 network_analyzer.py <options>
     ```

3. **Options**

   - `-all`: Analyze all packets.
   - `-tcp`: Analyze only TCP packets.
   - `-udp`: Analyze only UDP packets.
   - `-p <protocol>`: Analyze packets for a specific protocol (e.g., `http`, `https`, `ftp`, `smtp`, `dns`, `arp`).
   - `-ips <ip_address>`: Analyze packets with a specific source IP address.
   - `-ipd <ip_address>`: Analyze packets with a specific destination IP address.
   - `-ipt <ip_source_address> <ip_dest_address>`: Analyze packets with specific source and destination IP addresses.

4. **Output**

   - The script will generate text files (`all.txt`, `tcp.txt`, `udp.txt`, `http.txt`, `https.txt`, `ftp.txt`, `smtp.txt`, `dns.txt`, `ips.txt`, `ipd.txt`, `ipt.txt`) containing formatted packet information based on the selected options.

5. **Example**

   ```bash
   sudo python3 network_analyzer.py -p http
