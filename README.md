# mal-dnssearch

`Mal-dnssearch` is a robust shell script that compares IP and DNS <br>
addresses in logs against malware (and related) reputation data. <br>
It reports any matches and supports many log formats. <br>

Tested with Bash on OpenBSD, FreeBSD, Mac OSX, and Ubuntu.

## Installation:

Edit the Makefile or use the defaults to install the script. <br>
The *default* is to install to `/usr/local/mal-dnssearch`.
A symlink is then created in /usr/bin so that mal-dnssearch will most likely be in your PATH.

To install use:
```shell
sudo make install
```

To uninstall use:
```shell
sudo make uninstall
```

## Supported Logs (parses DNS names only):

Specify log type with `-T <type>`. This is used to parse the file correctly. <br>
`-f` is then required to specify the log file to read.

Type:      |    Description:
-----------|----------------
argus      |    ARGUS file (requires user data i.e. setting ARGUS_CAPTURE_DATA_LEN)
bind       |    ISC's BIND query log file
bro        |    BRO-IDS dns.log file
custom|ip  -    Custom file - IP addresses, one per line.
custom|dns -    Custom file - DNS (with one DNS name per line w/o trailing FQDN dot)
hosts      |    /etc/hosts file
httpry     |    HttPry log file
passivedns |    PassiveDNS log file
tcpdump    |    Tcpdump pcap file
tshark     |    Tshark pcap file
sonicwall  |    SonicWall NSA log file (via syslog)

Is your log not supported? E-mail me a sample, I'll add it.

## Supported Malware Host Lists:

Default is `http://secure.mayhemiclabs.com/malhosts/malhosts.txt` (DNS list) when
`-M` is not specified.

List:      |     Description:
-----------|-----------------
custom     |     Custom, one IP entry per line
snort      |     http://labs.snort.org/feeds/ip-filter.blf (IP)
et_ips     |     http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt (IP)
alienvault |     http://reputation.alienvault.com/reputation.generic (BIG file) (IP)
botcc      |     http://rules.emergingthreats.net/open/suricata/rules/botcc.rules (IP)
tor        | 	 http://rules.emergingthreats.net/open/suricata/rules/tor.rules (IP)
rbn        | 	 http://rules.emergingthreats.net/blockrules/emerging-rbn.rules (IP)
malhosts   |     http://www.malwaredomainlist.com/hostslist/hosts.txt (DNS)
malips     |     http://www.malwaredomainlist.com/hostslist/ip.txt (IP)
ciarmy     |     http://www.ciarmy.com/list/ci-badguys.txt (IP)
mayhemic   |     http://secure.mayhemiclabs.com/malhosts/malhosts.txt (DNS)
mandiant   | 	 https://raw.github.com/jonschipp/mal-dnssearch/master/mandiant_apt1.dns (DNS)

#### Todo (not ranked):

   * ~~Add iptables, PF, and IPFW support to block matches~~
   * ~~Allow multiple log files and types to be specified at once~~
   * ~~Add/fix counters~~
   * More efficient parsing
   * ~~Added two verbosity options~~
   * Add support for more logs (e-mail me with request and log sample)
   * ~~Read in alternative lists e.g. Emerging Threats, CIArmy~~
   * Check for necessary programs where needed e.g. bro-cut, ra, tcpdump, tshark
   * ~~Ability to read in file with IPs instead of names~~
   * ~~Add skip download option~~
   * Option to edit/change URLs in the script
   * Add cron mode option
   * Rewrite script in Python or C
   * Add option to download list only
   * See if you can read from the Collective Intelligence Framework database
   * Try optimizing with Gnu Parallel
   * See if there's a Team Cymru list to match against.
   * Add option to combine all IP and DNS lists into a single IP or DNS list. e.g. --all [dns|ip]
   * Add lists:
   	* http://www.dragonresearchgroup.org/insight/
    	* http://danger.rulez.sk/projects/bruteforceblocker/blist.php
    	* http://www.openbl.org/lists/date_all.txt
    	* http://www.mirc.com/servers.ini
    	* https://reputation.alienvault.com/reputation.data
   * Read from exported Sguil event logs
   * ~~Rewrite log options to use -L <log type>~~
   * ~~Rewrite malware host lists options to -M <list>~~
   * Replace awk with wc -l for line counting because it's much faster
   * Add apache logs
   * Fix "0 out of 0 entries matched" on second run bug
   * Add whitelist option to mal-dns2bro

## Usage:

### Non-mandatory options:

`-w` accept file with one entry per line or grep regex *e.g*. `-w "dont|match|these"`, `-w whitelist.txt` <br>
`-l` Log stdout & stderr to file  *e.g.* `-l /var/log/output.log` <br>
`-F` block matched hosts w/ firewall, 3 available: iptables, pf, ipfw *e.g.* `-F pf` <br>
`-N` skip file download <br>
`-p` Pass downloaded file to stdout to pipe to other programs *e.g.* <br>
	`-M mayhemic -p | mal-dns2bro -T dns > mayhemic.intel` <br>
`-v` Print line from mal-host list as its processed for debugging <br>
`-V` Print each line from the log file as its processed for debugging <br>

```shell
Usage: ./mal-dnssearch -T <type> -f <logfile> [-M <list>] [-w whitelist] [-l out.log] [-F firewall] [-N] [-vV]
```

### Examples:

```shell
./mal-dnssearch.sh -M mandiant (Downloads file only)
./mal-dnsearch.sh -T tshark -f dns.pcap
./mal-dnssearch.sh -T passivedns -f /var/log/passivedns/dmz.log -w whitelist.txt
./mal-dnsearch.sh -T bro -f /usr/local/bro/logs/current/dns.log \
	-w "company.com|abc.com|google|facebook" -l dns.results.log
./mal-dnsearch.sh -T bro -f /usr/local/bro/logs/current/dns.log -F iptables -l dns.results.log
./mal-dnsearch.sh -T argus -f dns.argus -M malhosts -F iptables -l dns.results.log
./mal-dnsearch.sh -T custom-ip -f iplist.log -M snort -l ip.results.log -N -v
./mal-dnsearch.sh -T custom-ip -f iplist.log -M mandiant -l ip.results.log
```

## Author:
***Jon Schipp*** (keisterstash) <br>
[More info](https://sickbits.net/finding-malware-by-dns-cache-snooping/) <br>
jonschipp [ at ] Gmail dot com <br>
`sickbits.net`, `jonschipp.com`
