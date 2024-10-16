"""
@author: Mona Kalaoun, Nikolas Pasichnik 
ECSE 316 - Assignment 1 
"""

import argparse
import random
import socket
import time

global request_type, header_temp, question_temp
labels = []

def parse_input():
    '''
    Parsing input from the cmd 
    '''
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

def create_dns_query(args): 
    '''
    Creating a DNS query based on the arguments provided in the cmd, and default values 
    '''
    global request_type, question_temp, header_temp

    # -- Creating DNS Packet Header --
    ID = str(hex(random.getrandbits(16)).replace('0x','').zfill(4))

    # Second Header Row (16 bits): |QR| Opcode |AA|TC|RD|RA| Z | RCODE | 
    QR = '0'
    OPCODE = '0000'
    AA = '0' 
    TC = '0' 
    RD = '1'
    RA = '0'
    Z = '000'
    RCODE = '0000' 
    second_header_row = str(hex(int(QR + OPCODE + AA + TC + RD + RA + Z + RCODE, 2)).replace('0x','').zfill(4))
    
    QDCOUNT = '0001'
    ANCOUNT = '0000'
    NSCOUNT = '0000'
    ARCOUNT = '0000'

    # The dns header is held in hexadecimal representation here 
    dns_header = ID + second_header_row + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    header_temp = dns_header

    # -- Creating DNS Question --
    QNAME = ''
    arg_list = (args.name).split('.')

    # Generating the QNAME content from inputted domain mame we are querying for 
    for label in arg_list: 
        # Concatenating the length of current label (in hex)
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
    question_temp = dns_question

    # Putting together the entire query 
    dns_query = dns_header + dns_question

    return bytes.fromhex(dns_query)

def send_query(query, args):
    '''
    Sending the created query to a DNS server using the inputted IP and Domain Name in the cmd 
    '''
    global request_type
    response=None

    print(f'DnsClient sending request for {args.name}')
    print(f'Server: {args.server[1:]}')
    print(f'Request type: {request_type}')

    # Creating UDP Socket 
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    sock.settimeout(args.t)

    max_retries = args.r
    retries = 0

    # Looping the request until it sends or max retry number reached 
    while retries <= max_retries:
        try:
            # Begin timer for the request
            start_time = time.time() 
            # Send query
            sock.sendto(query, (args.server[1:], args.p)) 
            # Receive query
            response, _ = sock.recvfrom(1024) 
            end_time = time.time() 
            # Computing total time needed to receive a response
            total_time = end_time - start_time 

            print(f'Response received after {total_time} seconds ({retries} retries)')
            response = response.hex()
            break
        except socket.timeout:
            retries += 1 
            if (retries > max_retries) :
                print(f"ERROR \t Maximum number of retries [{max_retries}] exceeded")
                break
            print(f"ERROR \t Timeout: Retransmitting query...")
            continue
        except Exception as e:
            print(f"ERROR \t Unexpected response: {e}")
            break

    return response     

def decode_label(data, index): 
    '''
    Decodes a single label (not a pointer) and returns the string equivalent 
    
    Example : 03 77 77 77 -> www
    '''

    # Decimal of hex length (ex: 03)
    label_length = int(data[index:index + 2], 16) 
    # Start decoding the letters (ex: now index is at the first 7)
    index += 2  
    label = "" 

    # Converting the ascii label into a real string 
    for _ in range(label_length):
        # Decode the character
        char = chr(int(data[index:index + 2], 16)) 
        # Append the character to the string 
        label += char 
        index += 2  
    
    # Returning the index because we want to continue from where we left off in the next label 
    return label, index 
 
def decode_pointer(response, offset): 
    '''
    Decodes a pointer recursively and returns the string equivalent of the label 
    '''
    
    # Get the starting point of the name stored in the pointer (ex: go back to qname)
    name = response[offset*2:] 
    index = 0
    temp_label = []

    # Loop until end of domain name is found ('00' indicates the end)
    while name[index:index+2] != "00": 
        
        # A nested pointer was found - must recursively run the decode_pointer function to obtain 
        if name[index:index+2]  == "c0":
            # Find hex offset of pointer and convert it to decimal 
            offset = int(name[index+2:index+4], 16)  
            temp_label += decode_pointer(response, offset)
            break  
        # Simple (uncompressed) label found -  need to decode
        else: 
            label, index = decode_label(name, index) 
            temp_label.append(label)

    return temp_label

# Main logic for decoding the name
def decode_name(data, response):
    '''
    Decodes a domain name from the DNS response, handling both uncompressed labels and compressed pointers. 
    Returns the full domain name along with the updated index position.
    '''
    i = 0
    label_array = []

    while (True): 
        # Compression identified, deal with pointers (c0 found)
        if data[i:i+2] == "c0": 
            # Find hex offset of pointer (byte after 'c0') and convert it to decimal 
            offset = int(data[i+2:i+4], 16) 
            label_array += decode_pointer(response, offset)
            # Next index after the entire pointer (ex: c010)
            i += 4 
            break
        # Uncompressed, decode label as is (not c0 or 00)
        elif data[i:i+2] != "00": 
            label, i = decode_label(data, i)
            label_array.append(label)
        else: 
            i+= 2
            break 
    
    # Connect the labels with periods (label1.label2.etc)
    return ".".join(label_array), i 

def parse_response(response): 
    '''
    Parses the DNS response received from a server and displays the required information. 
    '''
    global question_temp, header_temp

    # -- Retrieving the Header --
    header = response[0:24]
    response_id = header[0:4]
    query_id = header_temp[0:4]

    # Check response ID matches with query ID
    if (query_id != response_id):
        print('ERROR \t Unexpected response: Response ID does not match Query ID')
        return

    second_row = header[4:8]
    second_row = bin(int(second_row, 16)).replace('0b','')
    # QR = second_row[0:1] 
    # OPCODE = second_row[1:5]

    AA = second_row[5:6] 
    if AA == "1":
        auth = "auth"
    else:
        auth = "nonauth"
    
    # TC = second_row[6:7] 
    # RD = second_row[7:8]
    RA = second_row[8:9]
    if RA == "0":
        print('ERROR \t The server does not support recursive queries.')
    # Z = second_row[9:12]
    RCODE = int(second_row[12:16], 2) 

    if RCODE == 1:
        print('ERROR \t Format error: the name server was unable to interpret the query')
        exit()
    elif RCODE == 2:
        print('ERROR \t Server failure: the name server was unable to process this query due to a problem with the name server')
        exit()
    elif RCODE == 3 and AA == 1:
        print('NOTFOUND \t Name error: this code signifies that the domain name referenced in the query does not exist')
        exit()
    elif RCODE == 4:
        print('ERROR \t Not implemented: the name server does not support the requested kind of query')
        exit()
    elif RCODE == 5:
        print('ERROR \t Refused: the name server refuses to perform the requested operation for policy reasons')
        exit()
    elif RCODE < 0 or RCODE > 5:
        print('ERROR \t Unexpected response: RCODE value is not within the range [0,5]')

    # QDCOUNT = header[8:12]
    ANCOUNT = header[12:16]
    NSCOUNT = header[16:20]
    ARCOUNT = header[20:24]

    # -- Retrieving the question --
    # question = response[24:24+(len(question_temp))] 
  
    # -- Retrieving the answer --
    if (int(ANCOUNT,16) + int(ARCOUNT, 16) > 0):
        print(f'***Answer Section ({int(ANCOUNT,16)} records)***')

        record_offset = 0 
        records_treated = 0 
        # This is the WHOLE answer block (skipping header and question)
        answer = response[24+(len(question_temp)):]

        # Iterating while there's records to parse through 
        while records_treated < (int(ANCOUNT, 16) + int(NSCOUNT, 16) + int(ARCOUNT, 16)): 
            # Getting the data excluding the records already treated
            rdata = answer[record_offset:]
            # Decoding, and ignoring, the 'NAME' section of the answer 
            _, end = decode_name(rdata, response)

            # Getting other DNS Answers attributes 
            record_type = answer[record_offset+end:record_offset+end+4]
            record_class = answer[record_offset+end+4:record_offset+end+8]
            if record_class != "0001": print('ERROR \t Unexpected response: The value of the CLASS field in the DNS Answer is NOT 0x0001.')
            ttl = int(answer[record_offset+end+8:record_offset+ end+16], 16) 
            rdlength = int(answer[record_offset+end+16:record_offset+end+20], 16) 
            rdata = answer[record_offset+end+20:record_offset+end+20+rdlength*2]

            #This is the data block that represents the entire DNS Answer for one single record (used for offset) 
            answer_record = answer[record_offset: record_offset + end + 20+rdlength*2]

            # Only deal with the content if it's Answers or Additional Records (Authoritative Records are skipped)
            if records_treated < int(ANCOUNT, 16) or records_treated >= (int(ANCOUNT, 16) + int(NSCOUNT, 16)) : 
                # All normal Answer records have been treated, starting to treat Additional Records 
                if records_treated == int(ANCOUNT, 16): 
                    print(f"***Additional Section ({int(ARCOUNT, 16)} records)***")
                if record_type == "0001":
                    # Type A query 
                    # Obtaining the IP in format a.b.c.d
                    ip_a = str(int(rdata[0:2],16))
                    ip_b = str(int(rdata[2:4],16))
                    ip_c = str(int(rdata[4:6],16))
                    ip_d = str(int(rdata[6:8],16))
                    ip_full = ip_a+"."+ip_b+"."+ip_c+"."+ip_d
                    print(f"IP \t {ip_full} \t {ttl} \t {auth}")
                elif record_type == "0002":
                    # Type NS query
                    alias, _ = decode_name(rdata, response)
                    print(f"NS \t {alias} \t {ttl} \t {auth}")
                elif record_type == "0005":
                    # Type CNAME
                    alias, _ = decode_name(rdata, response)
                    print(f"CNAME \t {alias} \t {ttl} \t {auth}")
                elif record_type == "000f":
                    # Type MX query
                    preference = str(int(rdata[0:4], 16))
                    alias, _ = decode_name(rdata[4:], response)
                    print(f"MX \t {alias} \t {preference} \t {ttl} \t {auth}")
                else:
                    print('ERROR \t Unexpected response: Invalid record type')
            
            # Updating offset 
            record_offset = record_offset + len(answer_record)
            records_treated += 1 
    else:
        print("NOTFOUND")
        exit()

if __name__ == "__main__":
    args = parse_input()
    dns_query = create_dns_query(args)
    response = send_query(dns_query, args)
    if response != None: parse_response(response)     
