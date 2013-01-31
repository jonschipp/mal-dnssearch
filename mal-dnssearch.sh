#!/bin/bash

# print stats: kill -USR2 $pid
trap "stats" SIGUSR2

# functions
usage()
{
cat <<EOF

Compare DNS logs against known mal-ware host list
      Options
        -p      PassiveDNS log file
        -b      BRO-IDS dns.log file
        -w      Whitelist, accept file or argument
                e.g. -w "dont|match|these"
        -l      Log stdout & stderr to file

Usage: $0 [option] [dnslog]
e.g. $0 -p /var/log/pdns.log -l output.txt
EOF
}

stats()
{
echo " --> [-] stats: found: ${found}, current mal item: $tally of $total"
}

wlistchk()
{
if [ -z $WLISTDOM ]; then
echo "grep -v -E '(in-addr|\_)'"
elif [ -f $WLISTDOM ]; then
echo "grep -v -f $WLISTDOM"
else
echo "grep -v -E '(in-addr|$WLISTDOM)'"
fi
}

compare()
{
echo -e "\n[*] Results - ${FILE}: comparing $logttl entries\n"
while read bad_host
do
let tally++

for host in $(eval "$1")
do
if [ "$bad_host" == "$host" ]; then
echo "[+] Found - host '"$host"' matches "
let found++
break
fi

done
done < <(cut -f1 < malhosts.txt | sed -e '/^#/d' -e '/^$/d')
echo -e "--\n[=] $found of $total entries matched from malhosts.txt\n"
}

# test for argument
if [ ! $# -gt 1 ]; then
usage
exit 1
fi

# option and argument handling
while getopts "hp:b:w:l:" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         p)
             PDNS=1
             FILE=$OPTARG
             ;;
         b)
             BRO=1
             FILE=$OPTARG
             ;;
         w)
             WLISTDOM="$OPTARG"
             ;;
         l)
             LOG=1
             LOGFILE=$OPTARG
             ;;
         \?)
             exit 1
             ;;
     esac
done

echo -e "\nPID: $$"

# d/l malhost list
curl -O https://secure.mayhemiclabs.com/malhosts/malhosts.txt &>/dev/null

# vars
tally=0
found=0
total=$(sed -e '/^$/d' -e '/^#/d' < malhosts.txt | wc -l)
logttl=$(wc -l $FILE | awk '{ print $1 }')

# logging
if [ "$LOG" == 1 ]; then
exec > >(tee "$LOGFILE") 2>&1
echo -e "\n --> Logging stdout & stderr to $LOGFILE"
fi

# meat
if [ "$BRO" == 1 ]; then
compare "bro-cut query < \$FILE | $(eval wlistchk) | sort | uniq"
elif [ "$PDNS" == 1 ]; then
compare "sed 's/||/:/g' < \$FILE | $(eval wlistchk) | cut -d \: -f5 | sed 's/\.$//' | sort | uniq"
else
echo "Something isn't right!"
usage
exit 1
fi
