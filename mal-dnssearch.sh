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

Compare DNS/IP logs against known mal-ware host lists.
Default mal-list: http://secure.mayhemiclabs.com/malhosts/malhosts.txt

     Log File Options:
        -T <type>	Type(s) of log e.g. \`\`-T bro''
	-f <file>	Log file e.g. \`\`-f /opt/bro/logs/current/dns.log''

        Type:      |    Description:
	argus 	   - 	ARGUS file
	bind       -    ISC's BIND query log file
        bro        - 	BRO-IDS dns.log file
	custom-ip  -	Custom file - IP, one per line
	custom-dns -	Custom file - DNS, one per line
	hosts      -    /etc/hosts file
	httpry     -    HttPry log file
        passivedns -    PassiveDNS log file
        tcpdump    -	Tcpdump pcap file
	tshark     -	Tshark pcap file
	sonicwall  -	SonicWall NSA log file
		   |

      Malware List Options:
      -M <list>		Name of list, e.g. \`\`-M snort''

	List:      |     Description:
	snort 	   -     http://labs.snort.org/feeds/ip-filter.blf (IP)
	et_ips	   -     http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt (IP)
 	alienvault -     http://reputation.alienvault.com/reputation.generic (BIG file) (IP)
	botcc      -     http://rules.emergingthreats.net/open/suricata/rules/botcc.rules (IP)
	tor        -     http://rules.emergingthreats.net/open/suricata/rules/tor.rules (IP)
	rbn        -     http://rules.emergingthreats.net/blockrules/emerging-rbn.rules (IP)
	malhosts   -     http://www.malwaredomainlist.com/hostslist/hosts.txt (DNS)
	malips	   -     http://www.malwaredomainlist.com/hostslist/ip.txt (IP)
	ciarmy 	   -     http://www.ciarmy.com/list/ci-badguys.txt (IP)
	mayhemic   -     http://secure.mayhemiclabs.com/malhosts/malhosts.txt (DNS)
        mandiant   -     https://raw.github.com/jonschipp/mal-dnssearch/master/mandiant_apt1.dns (DNS)

      Processing Options:
	-h      help (this message)
	-F      insert firewall rules (blocks) e.g. iptables,pf,ipfw
        -l      Log stdout & stderr to <file>
	-N 	Skip file download
	-v	Verbose, echo each line line from mallist
	-V      More verbose, echo each line read from log + -v
        -w      Whitelist, accept <file> or regex
                e.g. -w "dont|match|these"

Usage: $0 -T <type> -f <logfile> [-M <list>] [-w whitelist] [-l out.log] [-F fw] [-#] [-N] [-vV]
e.g. $0 -T passivedns -f /var/log/pdns.log -w "facebook|google" -F iptables -l output.log
EOF
}

download()
{
if [ "$DOWNLOAD" != "NO" ]; then
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
if [ "$PARSE" == "alienvault" ]; then
	{ rm $MALHOSTFILE && awk '{ print $1 }' | sed -e '/^$/d' -e 's/^#//' > $MALHOSTFILE; } < $MALHOSTFILE
fi
if [ "$PARSE" == "botcc" ] || [ "$PARSE" == "tor" ] || [ "$PARSE" == "rbn" ]; then
	if [ "$DOWNLOAD" != "NO" ]; then
		{ rm $MALHOSTFILE && grep -o '\[.*\]' | sed -e 's/\[//;s/\]//' | awk 'BEGIN { RS="," } { print }' \
		| sed '/^$/d' > $MALHOSTFILE; } < $MALHOSTFILE
	fi
fi
if [ "$PARSE" == "malhosts" ]; then
	if [ "$DOWNLOAD" != "NO" ]; then
		{ rm $MALHOSTFILE && tr -d '\r' | sed -e '/^#/d' -e '/^$/d' | awk '{ print $2 }' > $MALHOSTFILE; } < $MALHOSTFILE
	fi
fi
if [ "$PARSE" == "malips" ] || [ "$PARSE" == "mandiant" ]; then
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
		echo "-log: $bad_host"
	fi

		for host in $(eval "$1")
		do
			if [ ${VERBOSE:-0} -gt 1 ]; then
				echo "---list: $host"
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
while getopts "hf:F:l:M:NT:vVw:" OPTION
do
     case $OPTION in
	 F)
	     FWTRUE=1
	     FW="$OPTARG"
	     ;;
         f)
	     FILE="$OPTARG"
	     ;;
         h)
             usage
             exit 1
             ;;
         l)
             LOG=1
             LOGFILE="$OPTARG"
             ;;
         M)
	     if [[ "$OPTARG" == snort ]]; then
	     		MALHOSTURL="http://labs.snort.org/feeds/ip-filter.blf"
	        	MALHOSTFILE="ip-filter.blf"
	     elif [[ "$OPTARG" == et_ips ]]; then
			MALHOSTURL="http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt"
       		  	MALHOSTFILE="compromised-ips.txt"
	     elif [[ "$OPTARG" == alienvault ]]; then
			MALHOSTURL="http://reputation.alienvault.com/reputation.generic"
       		  	MALHOSTFILE="reputation.generic"
			PARSE="$OPTARG"
	     elif [[ "$OPTARG" == botcc ]]; then
		        MALHOSTURL="http://rules.emergingthreats.net/open/suricata/rules/botcc.rules"
		  	MALHOSTFILE="botcc.rules"
			PARSE="$OPTARG"
	     elif [[ "$OPTARG" == tor ]]; then
			MALHOSTURL="http://rules.emergingthreats.net/open/suricata/rules/tor.rules"
		        MALHOSTFILE="tor.rules"
			PARSE="$OPTARG"
	     elif [[ "$OPTARG" == rbn ]]; then
			MALHOSTURL="http://rules.emergingthreats.net/blockrules/emerging-rbn.rules"
		       	MALHOSTFILE="emerging-rbn.rules"
			PARSE="$OPTARG"
	     elif [[ "$OPTARG" == malhosts ]]; then
			MALHOSTURL="http://www.malwaredomainlist.com/hostslist/hosts.txt"
		        MALHOSTFILE="hosts.txt"
			PARSE="$OPTARG"
			DNS=1
	     elif [[ "$OPTARG" == malips ]]; then
			MALHOSTURL="http://www.malwaredomainlist.com/hostslist/ip.txt"
       		  	MALHOSTFILE="ip.txt"
			PARSE="$OPTARG"
	     elif [[ "$OPTARG" == ciarmy ]]; then
			MALHOSTURL="http://www.ciarmy.com/list/ci-badguys.txt"
    		        MALHOSTFILE="ci-badguys.txt"
			PARSE="$OPTARG"
	     elif [[ "$OPTARG" == mandiant ]]; then
			MALHOSTURL="https://raw.github.com/jonschipp/mal-dnssearch/master/mandiant_apt1.dns"
		        MALHOSTFILE="mandiant_apt1.dns"
			PARSE="$OPTARG"
			DNS=1
	     elif [[ "$OPTARG" == mayhemic ]]; then
			MALHOSTURL="http://secure.mayhemiclabs.com/malhosts/malhosts.txt"
			MALHOSTFILE="malhosts.txt"
			PARSE="$OPTARG"
	     else
		      echo "Unknown reputation list!"
		      exit 1
	     fi
	     ;;
	 N)
             DOWNLOAD="NO"
             ;;
	 T)
	    	if [[ "$OPTARG" == argus ]]; then
			 ARGUS=1
	     	elif [[ "$OPTARG" == bind ]]; then
		      	 BIND=1
	     	elif [[ "$OPTARG" ==  bro ]]; then
		     	 BRO=1
	     	elif [[ "$OPTARG" == custom-ip ]]; then
			 CUSTOMIP=1
	     	elif [[ "$OPTARG" == custom-dns ]]; then
			 CUSTOMDNS=1
	     	elif [[ "$OPTARG" == hosts ]]; then
		     	 HOSTS=1
	     	elif [[ "$OPTARG" == httpry ]]; then
		     	 HTTPRY=1
	     	elif [[ "$OPTARG" == passivedns ]]; then
		     	 PDNS=1
	     	elif [[ "$OPTARG" == sonicwall ]]; then
		     	 SWALL=1
	     	elif [[ "$OPTARG" == tcpdump ]]; then
		     	 TCPDUMP=1
	     	elif [[ "$OPTARG" == tshark ]]; then
		     	 TSHARK=1
	     	else
		         echo "Unknown type!"
		         exit 1
	        fi
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
         \?)
             exit 1
             ;;
     esac
done

echo -e "\nPID: $$"

# vars
MALHOSTDEFAULT="http://secure.mayhemiclabs.com/malhosts/malhosts.txt"
MALFILEDEFAULT="malhosts.txt"

download
parse

# logging
if [ "$LOG" == 1 ]; then
	exec > >(tee "$LOGFILE") 2>&1
	echo -e "\n --> Logging stdout & stderr to $LOGFILE"
fi

# DNS parsing for log files
if [ "$BRO" == 1 ]; then
	PROG=BRO-IDS; COUNT=$(awk 'END { print NR }' $FILE)
	compare "bro-cut query < \$FILE | $(eval wlistchk) | sort | uniq"
fi
if [ "$PDNS" == 1 ]; then
	PROG=PassiveDNS; COUNT=$(awk 'END { print NR }' $FILE)
	compare "sed 's/||/:/g' < \$FILE | $(eval wlistchk) | cut -d \: -f5 | sed 's/\.$//' | sort | uniq"
fi
if [ "$HTTPRY" == 1 ]; then
	PROG=HttPry; COUNT=$(awk 'END { print NR }' $FILE)
	compare "awk '{ print $7 }' < \$FILE | $(eval wlistchk) | sed -e '/^-$/d' -e '/^$/d' | sort | uniq"
fi
if [ "$TSHARK" == 1 ]; then
	PROG=TShark; COUNT=$(awk 'END { print NR }' $FILE)
	compare "tshark -nr \$FILE -R udp.port==53 -e dns.qry.name -T fields 2>/dev/null \
	| $(eval wlistchk) | sed -e '/#/d' | sort | uniq"
fi
if [ "$TCPDUMP" == 1 ]; then
	PROG=TCPDump; COUNT=$(awk 'END { print NR }' $FILE)
	compare "tcpdump -nnr \$FILE udp port 53 2>/dev/null | grep -o 'A? .*\.' | $(eval wlistchk) \
	 | sed -e 's/A? //' -e '/[#,\)\(]/d' -e '/^[a-zA-Z0-9].\{1,4\}$/d' -e 's/\.$//'| sort | uniq"
fi
if [ "$ARGUS" == 1 ]; then
	PROG=ARGUS; COUNT=$(awk 'END { print NR }' $FILE)
	compare "ra -nnr \$FILE -s suser:512 - udp port 53 | $(eval wlistchk) | \
	sed -e 's/s\[..\]\=.\{1,13\}//' -e 's/\.\{1,20\}$//' -e 's/^[0-9\.]*$//' -e '/^$/d' | sort | uniq"
fi
if [ "$BIND" == 1 ]; then
	PROG=BIND; COUNT=$(awk 'END { print NR }' $FILE)
	compare "awk '/query/ { print \$15 } /resolving/ { print \$13 }' \$FILE | $(eval wlistchk) \
	| grep -v resolving | sed -e 's/'\"'\"'//g' -e 's/\/.*\/.*://' -e '/[\(\)]/d' | sort | uniq"
fi
if [ "$SWALL" == 1 ]; then
	PROG=SonicWALL; COUNT=$(awk 'END { print NR }' $FILE)
	compare "grep -h -o 'dstname=.* a' \$FILE 2>/dev/null | $(eval wlistchk) \
	| sed -e 's/dstname=//' -e 's/ a.*//' | sort | uniq"
fi
if [ "$HOSTS" == 1 ]; then
	PROG="Hosts File"; COUNT=$(awk 'END { print NR }' $FILE)
	compare "sed -e '/^$/d' -e '/^#/d' < \$FILE | $(eval wlistchk) | cut -f3 \
	| awk 'BEGIN { RS=\" \"; OFS = \"\n\"; ORS = \"\n\" } { print }' | sed '/^$/d' | sort | uniq"
fi
if [ "$CUSTOMDNS" == 1 ]; then
	PROG="Custom DNS File"; COUNT=$(awk 'END { print NR }' $FILE)
	compare "cat \$FILE | $(eval wlistchk) | sort | uniq"
fi

# IP parsing for log files
if [ "$CUSTOMIP" == 1 ]; then
	{ rm $MALHOSTFILE && sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq > $MALHOSTFILE; } < $MALHOSTFILE
	parse
	PROG="Custom IP File"; COUNT=$(awk 'END { print NR }' $FILE)
	compare "cat $FILE | $(eval wlistchk) | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq"
fi
