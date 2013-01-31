mal-dnssearch
=============

Compare BRO and PassiveDNS logs against known a malhosts list.
Downloads daily malhosts list and compares each entry to log
files.

SUPPORTED LOGS:
BRO-IDS - dns.log
PassiveDNS

TODO:
tcpdump pcaps
wireshark pcaps
httpry
ARGUS

USAGE:

Compare DNS logs against known mal-ware host list
      Options
        -p      PassiveDNS log file
        -b      BRO-IDS dns.log file
        -w      Whitelist, accept file or argument
                e.g. -w "dont|match|these"
        -l      Log stdout & stderr to file

Usage: $0 [option] [dnslog]

EXAMPLES:

./mal-dnssearch.sh -p /var/log/passivedns/dmz.log -w whitelist.txt -l /var/log/passivedns/dmz.results.log
./mal-dnssearch.sh -p /var/log/passivedns/dmz.log -w company.com
./mal-dnsearch.sh -b /usr/local/bro/logs/current/dns.log -w "company.com|abc.com|google|facebook" -l dns.results.log

MORE INFO:
https://sickbits.net/finding-malware-by-dns-cache-snooping/

