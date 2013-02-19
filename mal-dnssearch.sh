#!/bin/bash
# BSD License: 
# Copyright (c) 2013, Jon Schipp
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of 
# conditions and the following disclaimer. Redistributions in binary form must reproduce
# the above copyright notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
# SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# print stats: kill -USR2 $pid
trap "stats" SIGUSR2

# functions
usage()
{
cat <<EOF

Compare DNS/IP logs against known mal-ware host lists

     Log File Options:
	-a 	ARGUS file
        -b      BRO-IDS dns.log file
	-c      Custom file - DNS, one per line
        -d      Tcpdump pcap file
	-e      /etc/hosts file
	-i	ISC's BIND query log file 
        -p      PassiveDNS log file
	-o      SonicWall NSA log file
	-s      Tshark pcap file
	-t      HttPry log file
	-z      Custom file - IP, one per line

      Malware List Options:
	-0      Custom, one IP entry per line
	-1 	http://labs.snort.org/feeds/ip-filter.blf (IP)
	-2 	http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt (IP)
 	-3      http://reputation.alienvault.com/reputation.generic (BIG file) (IP)
	-4      http://rules.emergingthreats.net/open/suricata/rules/botcc.rules (IP)
	-5      http://rules.emergingthreats.net/open/suricata/rules/tor.rules (IP)
	-6      http://rules.emergingthreats.net/blockrules/emerging-rbn.rules (IP)
	-7 	http://www.malwaredomainlist.com/hostslist/hosts.txt (DNS)
	-8	http://www.malwaredomainlist.com/hostslist/ip.txt (IP)
	-9 	http://www.ciarmy.com/list/ci-badguys.txt (IP)

      Processing Options:
	-h      help (this message)
	-f      insert firewall rules (blocks) e.g. iptables,pf,ipfw
        -l      Log stdout & stderr to <file>
	-N 	Skip file download    
	-v	Verbose, echo each line line from mallist
	-V      More verbose, echo each line read from log + -v
        -w      Whitelist, accept <file> or regex
                e.g. -w "dont|match|these"

Usage: $0 <logoption> <logfile> [-w whitelist] [-l out.log] [-f fw][-#] [-N] [-vV]
e.g. $0 -p /var/log/pdns.log -w "facebook|google" -f iptables -l output.log
EOF
}

download()
{
if [ "$DOWNLOAD" != "NO" ] && [ "$PARSE" != "0"  ]; then 
	echo -e "\n[*] Downloading ${MALHOSTURL:-$MALHOSTDEFAULT}...\n"
	if command -v curl >/dev/null 2>&1; then
	curl --insecure -O ${MALHOSTURL:-$MALHOSTDEFAULT} 1>/dev/null

		if [ "$?" -gt 0 ]; then
		echo -e "\nDownload Failed! - Check URL"
		exit 1
		fi

	elif command -v wget >/dev/null 2>&1; then
	wget --no-check certificate ${MALHOSTURL:-$MALHOSTDEFAULT} 1>/dev/null

		if [ "$?" -gt 0 ]; then
		echo -e "\nDownload Failed! - Check URL"
		exit 1
		fi

	else
	echo -e "\nERROR: Neither cURL or Wget are installed or are not in the \$PATH!\n"
	exit 1
	fi
fi
total=$(sed -e '/^$/d' -e '/^#/d' < ${MALHOSTFILE:-$MALFILEDEFAULT} | awk 'END { print NR }' )
}

stats()
{
echo " --> [-] stats: found: ${found}, current mal item: $tally of $total"
}

wlistchk()
{
if [ -z $WLISTDOM ]; then
echo "grep -v -i -E '(in-addr|\_)'"
elif [ -f $WLISTDOM ]; then
echo "grep -v -i -f $WLISTDOM"
else
echo "grep -v -i -E '(in-addr|$WLISTDOM)'"
fi
}

parse()
{
if [ "$PARSE" == "3" ]; then
{ rm $MALHOSTFILE && awk '{ print $1 }' | sed -e '/^$/d' -e 's/^#//' > $MALHOSTFILE; } < $MALHOSTFILE
fi
if [ "$PARSE" == "4" ] || [ "$PARSE" == "5" ] || [ "$PARSE" == "6" ]; then
	if [ "$DOWNLOAD" != "NO" ]; then
	{ rm $MALHOSTFILE && grep -o '\[.*\]' | sed -e 's/\[//;s/\]//' -e 's/\,/\n/g' \
	| sed '/^$/d' > $MALHOSTFILE; } < $MALHOSTFILE
	fi
fi
if [ "$PARSE" == "7" ]; then
	if [ "$DOWNLOAD" != "NO" ]; then
	{ rm $MALHOSTFILE && tr -d '\r' | sed -e '/^#/d' -e '/^$/d' | awk '{ print $2 }' > $MALHOSTFILE; } < $MALHOSTFILE
	fi
fi
if [ "$PARSE" == "8" ]; then
{ rm $MALHOSTFILE && sed -e '/^$/d' -e '/^#/d' > $MALHOSTFILE; } < $MALHOSTFILE
fi
}

ipblock()
{
if [ "$FW" == "iptables" ]; then
iptables -A INPUT -s "$bad_host" -j DROP
iptables -A OUTPUT -s "$bad_host" -j DROP
iptables -A FORWARD -s "$bad_host" -j DROP
fi
if [ "$FW" == "pf" ]; then
echo -e "block in from "$bad_host" to any\n \
block out from "$bad_host" to any" | pfctl -a mal-dnssearch -f -
fi
if [ "$FW" == "ipfw" ]; then
ipfw add drop ip from "$bad_host" to any
ipfw add drop ip from any to "$bad_host"
fi
}

compare()
{
found=0
tally=0

echo -e "\n[*] |$PROG Results| - ${FILE}: $COUNT total entries\n"
while read bad_host
do
let tally++

	if [ ${VERBOSE:-0} -gt 0 ]; then
	echo $bad_host
	fi

		for host in $(eval "$1")
		do
			if [ ${VERBOSE:-0} -gt 1 ]; then
			echo $host
			fi 
			if [ "$bad_host" == "$host" ]; then
			echo "[+] Found - host '"$host"' matches "
			let found++
			if [ "$FWTRUE" == 1 ]; then
			ipblock
			fi
		break
			fi

		done

done < <(cut -f1 < ${MALHOSTFILE:-$MALFILEDEFAULT} | sed -e '/^#/d' -e '/^$/d')
echo -e "--\n[=] $found of $total entries matched from $MALHOSTFILE"
}

# if less than 1 argument
if [ ! $# -gt 1 ]; then
usage
exit 1
fi

# option and argument handling
while getopts "ha:b:c:d:e:f:g:i:l:Np:o:s:t:vVw:z:0:123456789" OPTION
do
     case $OPTION in
	 a)
	     ARGUS=1
	     ARGUSFILE="$OPTARG"
	     ;;
         b)
             BRO=1
             BROFILE="$OPTARG"
             ;;
	 c) 
	     CUSTOM=1
	     CUSTOMFILE="$OPTARG"
	     ;; 
	 d) 
             TCPDUMP=1
             TCPDUMPFILE="$OPTARG"
             ;;
	 e) 
	     HOSTS=1
	     HOSTSFILE="$OPTARG"
	     ;;
	 f)
	     FWTRUE=1
	     FW="$OPTARG"
	     ;;
         h)
             usage
             exit 1
             ;;
	 i) 
	     BIND=1
	     BINDFILE="$OPTARG"
	     ;; 
         l)
             LOG=1
             LOGFILE="$OPTARG"
             ;;
	 N) 
             DOWNLOAD="NO"
             ;;
         p)
             PDNS=1
             PDNSFILE="$OPTARG"
             ;;
	 o) 
	     SWALL=1
	     SWALLFILE="$OPTARG"
	     ;;
	 s) 
    	     TSHARK=1
  	     TSHARKFILE="$OPTARG"
	     ;;
	 t)
	     HTTPRY=1
             HTTPRYFILE="$OPTARG"
	     ;;
         w)
             WLISTDOM="$OPTARG"
             ;;
	 v) 
             VERBOSE=1
	     ;;
	 V) 
             VERBOSE=2
	     ;;
	 z) 
	     IP=1
	     IPFILE="$OPTARG"
	     ;;
	 0)
	     MALHOSTURL="none"
	     MALHOSTFILE="$OPTARG"
	     PARSE="$OPTION"
             ;;
	 1)
	     MALHOSTURL="http://labs.snort.org/feeds/ip-filter.blf"
	     MALHOSTFILE="ip-filter.blf"
             ;;
	 2)
	     MALHOSTURL="http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt"
	     MALHOSTFILE="compromised-ips.txt"
             ;;
	 3)
	     MALHOSTURL="http://reputation.alienvault.com/reputation.generic"
	     MALHOSTFILE="reputation.generic"
	     PARSE="$OPTION"
             ;;
	 4)
	     MALHOSTURL="http://rules.emergingthreats.net/open/suricata/rules/botcc.rules"
	     MALHOSTFILE="botcc.rules"
	     PARSE="$OPTION"
             ;;
	 5)
	     MALHOSTURL="http://rules.emergingthreats.net/open/suricata/rules/tor.rules"	
	     MALHOSTFILE="tor.rules"
	     PARSE="$OPTION"
             ;;
	 6)
	     MALHOSTURL="http://rules.emergingthreats.net/blockrules/emerging-rbn.rules"
	     MALHOSTFILE="emerging-rbn.rules"
	     PARSE="$OPTION"
             ;;
	 7)
	     MALHOSTURL="http://www.malwaredomainlist.com/hostslist/hosts.txt"
	     MALHOSTFILE="hosts.txt"
	     PARSE="$OPTION"
	     DNS=1
             ;;
	 8)
	     MALHOSTURL="http://www.malwaredomainlist.com/hostslist/ip.txt"
	     MALHOSTFILE="ip.txt"
	     PARSE="$OPTION"
             ;;
	 9)
	     MALHOSTURL="http://www.ciarmy.com/list/ci-badguys.txt"
	     MALHOSTFILE="ci-badguys.txt"
	     PARSE="$OPTION"
             ;;
         \?)
             exit 1
             ;;
     esac
done

echo -e "\nPID: $$"

# vars
MALHOSTDEFAULT="http://secure.mayhemiclabs.com/malhosts/malhosts.txt"
MALFILEDEFAULT="malhosts.txt"
if [ -z "$MALHOSTURL" ]; then
download
fi

# logging
if [ "$LOG" == 1 ]; then
exec > >(tee "$LOGFILE") 2>&1
echo -e "\n --> Logging stdout & stderr to $LOGFILE"
fi

# hack for -7, will fix later
if [ "$DNS" == "1" ]; then
download
parse
fi

# dns meat
if [ "$BRO" == 1 ]; then
FILE=$BROFILE; PROG=BRO-IDS; COUNT=$(awk 'END { print NR }' $BROFILE)
compare "bro-cut query < \$BROFILE | $(eval wlistchk) | sort | uniq"
fi
if [ "$PDNS" == 1 ]; then
FILE=$PDNSFILE; PROG=PassiveDNS; COUNT=$(awk 'END { print NR }' $PDNSFILE)
compare "sed 's/||/:/g' < \$PDNSFILE | $(eval wlistchk) | cut -d \: -f5 | sed 's/\.$//' | sort | uniq"
fi
if [ "$HTTPRY" == 1 ]; then
FILE=$HTTPRYFILE; PROG=HttPry; COUNT=$(awk 'END { print NR }' $HTTPRYFILE)
compare "awk '{ print $7 }' < \$HTTPRYFILE | $(eval wlistchk) | sed -e '/^-$/d' -e '/^$/d' | sort | uniq"
fi
if [ "$TSHARK" == 1 ]; then
FILE=$TSHARKFILE; PROG=TShark; COUNT=$(awk 'END { print NR }' $TSHARKFILE)
compare "tshark -nr \$TSHARKFILE -R udp.port==53 -e dns.qry.name -T fields 2>/dev/null \
| $(eval wlistchk) | sed -e '/#/d' | sort | uniq"
fi
if [ "$TCPDUMP" == 1 ]; then
FILE=$TCPDUMPFILE; PROG=TCPDump; COUNT=$(awk 'END { print NR }' $TCPDUMPFILE)
compare "tcpdump -nnr \$TCPDUMPFILE udp port 53 2>/dev/null | grep -o 'A? .*\.' | $(eval wlistchk) \
 | sed -e 's/A? //' -e '/[#,\)\(]/d' -e '/^[a-zA-Z0-9].\{1,4\}$/d' -e 's/\.$//'| sort | uniq"
fi
if [ "$ARGUS" == 1 ]; then
FILE=$ARGUSFILE; PROG=ARGUS; COUNT=$(awk 'END { print NR }' $ARGUSFILE)
compare "ra -nnr \$ARGUSFILE -s suser:512 - udp port 53 | $(eval wlistchk) | \
sed -e 's/s\[..\]\=.\{1,13\}//' -e 's/\.\{1,20\}$//' -e 's/^[0-9\.]*$//' -e '/^$/d' | sort | uniq"
fi
if [ "$BIND" == 1 ]; then
FILE=$BINDFILE; PROG=BIND; COUNT=$(awk 'END { print NR }' $BINDFILE)
compare "awk '/query/ { print \$15 } /resolving/ { print \$13 }' \$BINDFILE | $(eval wlistchk) \ 
| grep -v resolving | sed -e 's/'\"'\"'//g' -e 's/\/.*\/.*://' -e '/[\(\)]/d' | sort | uniq"
fi 
if [ "$SWALL" == 1 ]; then
FILE=$SWALLFILE; PROG=SonicWALL; COUNT=$(awk 'END { print NR }' $SWALLFILE)
compare "grep -h -o 'dstname=.* a' \$SWALLFILE 2>/dev/null | $(eval wlistchk) \
| sed -e 's/dstname=//' -e 's/ a.*//' | sort | uniq"
fi 
if [ "$HOSTS" == 1 ]; then
FILE=$HOSTSFILE; PROG="Hosts File"; COUNT=$(awk 'END { print NR }' $HOSTSFILE)
compare "sed -e '/^$/d' -e '/^#/d' < \$HOSTSFILE | $(eval wlistchk) | cut -f3 \
| awk 'BEGIN { RS=\" \"; OFS = \"\n\"; ORS = \"\n\" } { print }' | sed '/^$/d' | sort | uniq"
fi
if [ "$CUSTOM" == 1 ]; then
FILE=$CUSTOMFILE; PROG="Custom File"; COUNT=$(awk 'END { print NR }' $CUSTOMFILE)
compare "cat \$CUSTOMFILE | $(eval wlistchk) | sort | uniq"
fi
# ip meat
if [ "$IP" == 1 ]; then
download
{ rm $MALHOSTFILE && sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq > $MALHOSTFILE; } < $MALHOSTFILE
parse
FILE=$IPFILE; PROG="Custom IP File"; COUNT=$(awk 'END { print NR }' $IPFILE)
compare "cat $IPFILE | $(eval wlistchk) | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq"
fi
