# DNS Client
This program implements a Domain Name System (DNS) client using Python sockets to perform various DNS queries such as A, NS, and MX records.

To invoke the DNS Client, the following syntax must be used in the command line: 

`python dnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name`

where:

- timeout (optional): Timeout time to wait before retransmitting an unanswered query in seconds

- max-retries (optional): Maximum number of times to retransmit an unanswered query before giving up

- port (optional): UDP port number of the DNS server

- mx (optional flag): Send a MX (mail server) query'

- ns (optional flag): Send a NS (name server) query

- server (required): IPv4 address of the DNS server, in a.b.c.d format

- name (required): Domain name to query for
  
Note that this code was written and executed in the Visual Studio Code terminal on a Windows 10 (vers. 22H2) machine using Python version 3.11.5


