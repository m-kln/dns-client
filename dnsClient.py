import argparse
import random
import socket
import time

global request_type, header_temp, question_temp, labels
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
    RCODE = '0000' #response
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
            
    parseResponse(response)     
    return response     

####################################### THE FUN STUFF STARTS HERE ########################################################

# I am a very modular person so I created 3 new functions for decoding
# I added a new global variable: labels

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
    global labels
    
    name = response[offset*2:] # find the starting point of the name stored in the pointer in the entire response (ex: go back to qname)
    # message can basically be for ex: qname + the rest. Cant set an end index cuz we dont know how long the name stored in the pointer is 
    index = 0

    while name[index:index+2] != "00": # 00 indicates end of name
       label, index = decode_label(name, index) # decode each label in the stored name
       labels.append(label)

# Main logic for decoding the name
def decodeName(rdata, response):
    global labels
    i = 0

    while i < len(rdata): # len(rdata) =  rdlength * 2 
        if rdata[i:i+2] == "c0": #if position starts with c0 -> pointer so the next byte is the offset. ex: c010
            offset = rdata[i+2:i+4] # find hex offset (10)
            offset = int(offset, 16) # convert into decimal (16)
            decode_pointer(response, offset)
            i += 4 # next index after the entire pointer (ex: c010)
        else: #if not pointer -> normal decoding
            label, i = decode_label(rdata, i)
            labels.append(label)

    return ".".join(labels) # connect the labels with periods label1.label2.etc

def parseResponse(response): 
    global question_temp, header_temp

    print("Response: " + response) 
    #print(len(response))

    # ========================================= Retrieving the Header =========================================
    header = response[0:24]
    #print("Header: \n"+header)
    # print(len(header))
    # Getting the ANCOUNT, NSCOUNT and ARCOUNT
    ID = header[0:4]

    second_row = header[4:8]
    # print("Second Row: "+second_row)
    second_row = bin(int(second_row, 16)).replace('0b','')
    # print(len(second_row))
    # print(second_row)
    # Breaking down the second row further: 
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
    # print(QR + "" + OPCODE + "" + AA + "" +  TC + "" +  RD + "" + RA + "" + Z + "" +  RCODE )

    QDCOUNT = header[8:12]
    ANCOUNT = header[12:16]
    NSCOUNT = header[16:20]
    ARCOUNT = header[20:24]

    # print("ID: "+ID)
    # print("QDCOUNT: "+QDCOUNT)
    # print("ANCOUNT: "+ANCOUNT)
    # print("NSCOUNT: "+NSCOUNT)
    # print("ARCOUNT: "+ARCOUNT)

    # =========================================== Retrieving the question ===========================================
    # The length of the question depends on the length of the website name!!
    question = response[24:24+(len(question_temp))] 
    # print("Question: \n"+question)

    # ============================================= Retrieving the answer =============================================
    if (int(ANCOUNT,16) != 0):
        print(f'***Answer Section ({int(ANCOUNT,16)} records)***')
        # Possible while loop here (see TODO)
        answer = response[24+(len(question_temp)):]
        print("Answer: "+answer)
        # print(len(answer))
        pointer = answer[0:4]
        # print("pointer-test: "+str(bin(int(pointer, 16))).replace('0b',''))
        response_type = answer[4:8]
        response_class = answer[8:12]
        TTL = answer[12:20]
        ttl = int(TTL, 16)
        RDLENGTH = answer[20:24]
        rdlength_int=int(RDLENGTH, 16)
        rdata = answer[24:24+rdlength_int*2]
        '''print("Pointer: "+pointer)
        print("Response Type: "+response_type)
        print("Response Class: "+response_class)
        print("TTL: "+TTL)
        #print("RDLENGTH: " + str(rdlength_int))
        print("IP: "+rdata)'''

        if response_type == "0001":
            # ---- Type A query ----
            # Converting the IP 
            # Assume IP = a.b.c.d
            ip_a = str(int(rdata[0:2],16))
            ip_b = str(int(rdata[2:4],16))
            ip_c = str(int(rdata[4:6],16))
            ip_d = str(int(rdata[6:8],16))
            ip_full = ip_a+"."+ip_b+"."+ip_c+"."+ip_d
            #print("IP Address = "+ip_a+"."+ip_b+"."+ip_c+"."+ip_d)

            print(f"IP \t {ip_full} \t {ttl} \t {auth}")
        elif response_type == "0002":
            # Type NS query
            alias = decodeName(rdata, response)
            print(f"NS \t {ip_full} \t {ttl} \t {auth}")
        elif response_type == "0005":
            # Type CNAME
            alias = decodeName(rdata, response)
            print(f"CNAME \t {alias} \t {ttl} \t {auth}")
        elif response_type == "000f":
            # Type MX query
            alias = decodeName(rdata, response)
            print(f"IP \t {ip_full} \t {ttl} \t {auth}")
        else:
            print("error")

   
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    '''
    TODO

    - Ex for Type A, there are 2 records in Answer. Currenty we handle one.
        - Possible logic: Add while loop in answer section that loops twice (aka for the same number of records present). 
        - Need to make sure that we parse the second answer correctly cuz rn we only look at the first. Everything is hardcoded at the moment
        - Ex: 
            Complete Answer section: c00c000500010000080a000e087765626361636865026974c010c02b00010001000000e5000484d8b19d
            Answer 1: c00c000500010000080a000e087765626361636865026974c010 (the one we have handled)
            Answer 2: c02b00010001000000e5000484d8b19d (type is A so there must be a second line that prints the IP)
    
    -  Output correct error messages for RCODE (p2-3 of dnsprimer)    

    -  rdata for type MX has a different format so need to look into this
    
    '''

if __name__ == "__main__":
    args = parseInput()
    dns_query = createDnsQuery(args)
    sendQuery(dns_query, args)