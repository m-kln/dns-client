import argparse
import random
import socket
import time

global request_type, header_temp, question_temp
labels = []

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
    global request_type, question_temp, header_temp

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
    RCODE = '0000' 
    second_header_row = str(hex(int(QR + OPCODE + AA + TC + RD + RA + Z + RCODE, 2)).replace('0x','').zfill(4))
    QDCOUNT = '0001'
    ANCOUNT = '0000'
    NSCOUNT = '0000'
    ARCOUNT = '0000'

    # The dns header is held in hexadecimal representation here 
    dns_header = ID + second_header_row + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    header_temp = dns_header

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
    question_temp = dns_question

    # Putting together the entire query 
    dns_query = dns_header + dns_question

    return bytes.fromhex(dns_query)

def sendQuery(query, args):
    global request_type

    response=None

    print(f'DnsClient sending request for [{args.name}]')
    print(f'Server: [{args.server[1:]}]')
    print(f'Request type: [{request_type}]')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Create UDP socket
    sock.settimeout(args.t)

    max_retries = args.r
    retries = 0

    while retries <= max_retries:
        try:
            start_time = time.time() # begin timer for the request
            sock.sendto(query, (args.server[1:], args.p)) # send query
            response, _ = sock.recvfrom(1024) # receive query
            end_time = time.time() # end the timer 
            total_time = end_time - start_time # total time needed to receive a response
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
            
    if response != None: parseResponse(response)     
    return response     

# Function that decodes a label (not a pointer)
def decode_label(rdata, index): 
    #ex : 03 77 77 77 -> www
    label_length = int(rdata[index:index + 2], 16)  # decimal of hex length (ex: 03)
    index += 2  # start decoding the letters (ex: now index is at the first 7)
    label = "" 

    for _ in range(label_length): # ex: label_length = 3 -> 3 loops (1 for each char)
        char = chr(int(rdata[index:index + 2], 16))  # Decode each character
        label += char # Add each char to the label string to create the word
        index += 2  # Next character 
    
    return label, index # returning the index because we want to continue from where we left off in the next label 

# Function that decodes pointers 
def decode_pointer(response, offset): 
    
    name = response[offset*2:] # find the starting point of the name stored in the pointer in the entire response (ex: go back to qname)
    # message can basically be for ex: qname + the rest. Cant set an end index cuz we dont know how long the name stored in the pointer is 
    index = 0
    temp_label = []
    while name[index:index+2] != "00": # 00 indicates end of name
        
        # A nested pointer was found - must recursively run the decode_pointer function to obtain 
        if name[index:index+2]  == "c0":
           offset = name[index+2:index+4] # find hex offset (10)
           offset = int(offset, 16) # convert into decimal (16)
           temp_label += decode_pointer(response, offset)
           break 
        
        # It's a simple(uncompressed) label which needs to be decoded
        else: 
            label, index = decode_label(name, index) # decode each label in the stored name
            temp_label.append(label)

    return temp_label

# Main logic for decoding the name
def decodeName(rdata, response):
    i = 0
    labels_test = []

    while (True): 

        # Compression identified, deal with pointers
        if rdata[i:i+2] == "c0": #if position starts with c0 -> pointer so the next byte is the offset. ex: c010
            offset = rdata[i+2:i+4] # find hex offset (10)
            offset = int(offset, 16) # convert into decimal (16)
            labels_test += decode_pointer(response, offset)
            i += 4 # next index after the entire pointer (ex: c010)
            break
        # Uncompressed, decode label as is 
        elif rdata[i:i+2] != "00": #if not pointer & not zero-octet -> it's a normal label 
            label, i = decode_label(rdata, i)
            labels_test.append(label)
        # elif i >= len(rdata): #not sure if this piece matters, test and then remove if useless
        #     break 
        else: #Case where it's the zero octet (need to increment index) 
            i+= 2
            break 
        
    return ".".join(labels_test), i # connect the labels with periods label1.label2.etc

def parseResponse(response): 
    global question_temp, header_temp

    # ========================================= Retrieving the Header =========================================
    header = response[0:24]
    ID = header[0:4] #need to check response id matches with query 

    second_row = header[4:8]
    second_row = bin(int(second_row, 16)).replace('0b','')
    QR = second_row[0:1] #somewhat important 
    OPCODE = second_row[1:5]
    AA = second_row[5:6] #important for authoritative or not 
    if AA == "1":
        auth = "auth"
    else:
        auth = "nonauth"

    TC = second_row[6:7] #sure important too
    RD = second_row[7:8]
    RA = second_row[8:9] #sure recursive queries 
    Z = second_row[9:12]
    RCODE = second_row[12:16] #important yes 
    rcode = int(RCODE, 2) #get int of RCODE

    if rcode == 1:
        print('ERROR \t Format error: the name server was unable to interpret the query')
        exit()
    elif rcode == 2:
        print('ERROR \t Server failure: the name server was unable to process this query due to a problem with the name server')
        exit()
    elif rcode == 3 and AA == 1:
        print('NOTFOUND \t Name error: this code signifies that the domain name referenced in the query does not exist')
        exit()
    elif rcode == 4:
        print('ERROR \t Not implemented: the name server does not support the requested kind of query')
        exit()
    elif rcode == 5:
        print('ERROR \t Refused: the name server refuses to perform the requested operation for policy reasons')
        exit()
    elif rcode != 0:
        exit()

    QDCOUNT = header[8:12]
    ANCOUNT = header[12:16]
    NSCOUNT = header[16:20]
    ARCOUNT = header[20:24]

    # =========================================== Retrieving the question ===========================================
    # The length of the question depends on the length of the website name!!
    # (hardcoded 24 -> header is always 24)
    question = response[24:24+(len(question_temp))] 

    # ============================================= Retrieving the answer =============================================
    if (int(ANCOUNT,16) + int(ARCOUNT, 16) > 0): #technically this if is not needed 
        print(f'***Answer Section ({int(ANCOUNT,16)} records)***')

        record_offset = 0 
        records_treated = 0 
        # This is the WHOLE answer block (skipping header and question)
        answer = response[24+(len(question_temp)):]

        while records_treated < (int(ANCOUNT, 16) + int(NSCOUNT, 16) + int(ARCOUNT, 16)): 
            # Getting the data from beginning of the Answer section until the end 
            rdata = answer[record_offset:] #for NAME section 
            _, end = decodeName(rdata, response)

            response_type = answer[record_offset+end:record_offset+end+4]
            TTL = answer[record_offset+end+8:record_offset+ end+16]
            ttl = int(TTL, 16)
            RDLENGTH = answer[record_offset+end+16:record_offset+end+20]
            rdlength_int=int(RDLENGTH, 16)
            rdata = answer[record_offset+end+20:record_offset+end+20+rdlength_int*2]

            #This is the block that represents the entire answer data for one answer record 
            answer_record = answer[record_offset: record_offset + end + 20+rdlength_int*2]

            # Only deal with the content if it's Answers or Additional Records (Authoritative Records are skipped)
            if records_treated < int(ANCOUNT, 16) or records_treated >= (int(ANCOUNT, 16) + int(NSCOUNT, 16)) : 
                if response_type == "0001":
                    # ---- Type A query ----
                    # Converting the IP 
                    # Assume IP = a.b.c.d
                    ip_a = str(int(rdata[0:2],16))
                    ip_b = str(int(rdata[2:4],16))
                    ip_c = str(int(rdata[4:6],16))
                    ip_d = str(int(rdata[6:8],16))
                    ip_full = ip_a+"."+ip_b+"."+ip_c+"."+ip_d
                    print(f"IP \t {ip_full} \t {ttl} \t {auth}")
                elif response_type == "0002":
                    # Type NS query
                    alias, _ = decodeName(rdata, response)
                    print(f"NS \t {alias} \t {ttl} \t {auth}")
                elif response_type == "0005":
                    # Type CNAME
                    alias, _ = decodeName(rdata, response)
                    print(f"CNAME \t {alias} \t {ttl} \t {auth}")
                elif response_type == "000f":
                    # Type MX query
                    preference = str(int(rdata[0:4], 16))
                    alias, _ = decodeName(rdata[4:], response)
                    print(f"MX \t {alias} \t {preference} \t {ttl} \t {auth}")
                else:
                    print("error") #need to change this prolly
            
            # Updating offset 
            record_offset = record_offset + len(answer_record)
            records_treated += 1 

   
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    '''
    TODO

    -  If there are records in the "Additional" section, then we must also print them (idk what we can use to test this, but it's part of the doc) 
    -  `python dnsClient.py -t 10 -r 2 -mx @132.206.85.18 mcgill.ca` <=== This could be used to test this allegedly 
    -  ^^^^ This should be supported now, need to test it (i dont have the mcgill vpn) 
    
    -  Some more error handling maybe? Could be more robust 

    -  finalize + cleanup?? im not sure if we have anything else to do 
    
    '''

if __name__ == "__main__":
    args = parseInput()
    dns_query = createDnsQuery(args)
    sendQuery(dns_query, args)