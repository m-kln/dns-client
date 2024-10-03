import argparse
import random

global request_type

def parseInput():
    parser = argparse.ArgumentParser(usage='dnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name')
    parser.add_argument('-t', type=int, default=5, metavar='timeout', help='Timeout time to wait before retransmitting an unanswered query in seconds')
    parser.add_argument('-r', type=int, default=3, metavar='max-retries', help='Maximum number of times to retransmit an unanswered query before giving up')
    parser.add_argument('-p', type=int, default=53, metavar='port', help='UDP port number of the DNS server')

    mx_ns = parser.add_mutually_exclusive_group()
    mx_ns.add_argument('-mx', action='store_true', help='Send a MX (mail server) query')
    mx_ns.add_argument('-ns', action='store_true', help='Send a NS (name server) query')

    parser.add_argument('server', type=str, help='IPv4 address of the DNS server, in a.b.c.d format')
    parser.add_argument('name', type=str, help='Domain name to query for')

    return parser.parse_args()

def createDnsQuery(args): 
    global request_type

    # === Creating Header ===
    ID = str(hex(random.getrandbits(16)).replace('0x','').zfill(4))

    # Second Header Row (16 bits): |QR| Opcode |AA|TC|RD|RA| Z | RCODE | 
    QR = '0'
    OPCODE = '0000'
    AA = '0' 
    TC = '0' 
    RD = '1'
    RA = '0'
    Z = '000'
    RCODE = '0000' #response
    second_header_row = str(hex(int(QR + OPCODE + AA + TC + RD + RA + Z + RCODE, 2)).replace('0x','').zfill(4))

    QDCOUNT = '0001'
    ANCOUNT = '0000'
    NSCOUNT = '0000'
    ARCOUNT = '0000'

    # The dns header is held in hexadecimal representation here 
    dns_header = ID + second_header_row + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    # === Creating Question ===
    QNAME = ''
    arg_list = (args.name).split('.')

    for label in arg_list: 
        # Concatenating the length of current label 
        QNAME += str(hex(len(label)).replace('0x','').zfill(2))

        # Concatenating the hex ascii value of each character in the current label
        for character in label: 
            QNAME += str(hex(ord(character)).replace('0x','').zfill(2))
   
    # Signaling the ending of the QNAME
    QNAME += '00'
    
    if (args.ns) : 
        # 0x0002 for a type-NS query (name server)
        QTYPE = '0002'
        request_type = "NS"
    elif (args.mx) : 
        # 0x000f for a type-MX query (mail server) 
        QTYPE = '000f'
        request_type = "MX"
    else: 
        # 0x0001 for a type-A query (host address) 
        QTYPE = '0001'
        request_type = "A" 

    QCLASS = '0001'

    # Dont need to convert this to hex, everything is already in hex 
    dns_question = QNAME + QTYPE + QCLASS 

    # Putting together the entire query 
    dns_query = dns_header + dns_question

    print(dns_query)

    return bytes.fromhex(dns_query)

if __name__ == "__main__":
    args = parseInput()
    dns_query = createDnsQuery(args)