import argparse

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

if __name__ == "__main__":
    args = parseInput()
    print(args.name)