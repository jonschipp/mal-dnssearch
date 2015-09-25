#!/usr/bin/env bash

# functions
usage()
{
cat <<EOF

Prepares a reputation list for Bro's Intel Framework.
Designed to work with mal-dnssearch, but will work with
any list of Bro indicator types where each entry is on
a single line by itself.

	Add lines to local.bro or similar to load the Intel Framework:
	@load frameworks/intel/seen
	@load frameworks/intel/do_notice

	redef Intel::read_files += {
	    "/opt/bro/share/bro/site/mandiant.intel",
	    "/opt/bro/share/bro/site/malhosts.intel",
	    };

     Options:
        -T <type>	Intel::Type value or short name (e.g. \`\`-T ip'', \`\`-T Intel::ADDR'')
			Intel::ADDR		ip
			Intel::DOMAIN		dns
		       	Intel::URL		url
			Intel::SOFTWARE		software
			Intel::EMAIL 		e-mail
			Intel::USER_NAME	user
			Intel::FILE_HASH	filehash
			Intel::FILE_NAME	filename
			Intel::CERT_HASH	certhash

	-f <file>	Read parsed list from file (if option is ommited, use stdin)
	-i <location>	Location seen in Bro (def: null)
	-n <boolean>	Call Notice Framework on matches, 'true/false' (def: false)
	-s <name>	Name for data source (def: mal-dnssearch)
	-u <url>	URL of feed (if applicable)
	-d <desc>       meta.desc - 
	-g <severity>   meta.cif_severity
	-k <impact>	meta.cif_impact
	-w <pattern>	Whitelist pattern (e.g. \`\`-w "192\.168"'', \`\`-w "bad|host|evil"''
			Or set \$WHITELIST in your shell (e.g. \`\`export WHITELIST="you|get|clipped"'')

Usage: $0 -T <type> [ -f <logfile> ] [ -s <name> ] [ -n <boolean> ] [ -i <location> ] [ -u <url> ] [ -w <pattern> ]
e.g.
> ./mal-dnssearch.sh -M mayhemic -p | $0 -T dns > mayhemic.intel
> $0 -T dns -f apt1.list -s mandiant -n true -i HTTP::IN_HOST_HEADER > mandiant.intel
EOF
}

argcheck() {
# if less than n argument
if [ $ARGC -lt $1 ]; then
        echo "Missing arguments! Use \`\`-h'' for help."
        exit 1
fi
}

format() {

	echo -e "\n[*] Waiting for input.. (Did you pipe stdin or specify a file?)\n" 1>&2

awk -v type=$TYPE -v source=$SOURCE -v url=$URL -v notice=$NOTICE -v if_in=$IF_IN -v wlist=$WLIST -v desc=$DESC -v cif_severity=$CIF_SEVERITY -v cif_impact=$CIF_IMPACT 'BEGIN \
        {
	       	print "#fields\tindicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\tmeta.if_in\tmeta.whitelist\tmeta.desc\tmeta.cif_severity\tmeta.cif_impact"
	}
	{
		$2=type; $3=source; $4=url; $5=notice; $6=if_in; $7=wlist; $8=desc; $9=cif_severity; $10=cif_impact;
		print $1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6"\t"$7"\t"$8"\t"$9"\t"$10;
	}'

}

whitelist()
{
if [ -z $WHITELIST ]; then
        echo "grep -v -i -E '___somestringthatwontmatch___'"
elif [ -f $WHITELIST ]; then
        echo "grep -v -i -f $WHITELIST"
else
        echo "grep -v -i -E '(somestringthatwontmatch|$WHITELIST)'"
fi
}

# Initializations
SOURCE="mal-dnssearch"
NOTICE="F"
URL="-"
IF_IN="-"
WLIST="-"
DESC="-"
CIF_SEVERITY="-"
CIF_IMPACT="-"
ARGC=$#
FILE_SET=0
TYPE_SET=0

argcheck 1

while getopts "hd:f:g:k:i:n:T:s:u:w:" OPTION
do
     case $OPTION in
	 g) CIF_SEVERITY="$OPTARG"
	     ;;
	 k) CIF_IMPACT="$OPTARG"
	     ;;
	 d) DESC="$OPTARG"
	     ;;
         f)
	     FILE="$OPTARG"
	     FILE_SET=1
	     ;;
	 h)
	     usage
	     exit 0
  	     ;;
	 i)
	     IF_IN="$OPTARG"
	     ;;
	 n)
	     if [[ "$OPTARG" == true ]]; then
             	     NOTICE="T"
	     elif [[ "$OPTARG" == false ]]; then
		     NOTICE="F"
	     else
		     echo "Unknown notice value!"
                     exit 1
             fi
 	     ;;
	 T)
	     if [[ "$OPTARG" == ip ]] || [[ "$OPTARG" == "Intel::ADDR" ]]; then
             	     TYPE=Intel::ADDR
	     elif [[ "$OPTARG" == dns ]] || [[ "$OPTARG" == "Intel::DOMAIN" ]]; then
		     TYPE=Intel::DOMAIN
	     elif [[ "$OPTARG" == e-mail ]] || [[ "$OPTARG" == "Intel::EMAIL" ]]; then
		     TYPE=Intel::EMAIL
	     elif [[ "$OPTARG" == url ]] || [[ "$OPTARG" == "Intel::URL" ]]; then
		     TYPE=Intel::URL
	     elif [[ "$OPTARG" == software ]] || [[ "$OPTARG" == "Intel::SOFTWARE" ]]; then
		     TYPE=Intel::SOFTWARE
	     elif [[ "$OPTARG" == user ]] || [[ "$OPTARG" == "Intel::USER_NAME" ]]; then
		     TYPE=Intel::USER_NAME
	     elif [[ "$OPTARG" == filehash ]] || [[ "$OPTARG" == "Intel::FILE_HASH" ]]; then
		     TYPE=Intel::FILE_HASH
	     elif [[ "$OPTARG" == filename ]] || [[ "$OPTARG" == "Intel::FILE_NAME" ]]; then
		     TYPE=Intel::FILE_NAME
	     elif [[ "$OPTARG" == certhash ]] || [[ "$OPTARG" == "Intel::CERT_HASH" ]]; then
		     TYPE=Intel::CERT_HASH
	     else
		     echo "Unknown type!"
                     exit 1
             fi
	     TYPE_SET=1
	     ;;
	 s)
 	     SOURCE="$OPTARG"
  	     ;;
	 u)
	     URL="$OPTARG"
             ;;
	 w)
	     if [ -z $WHITELIST ]; then
		     WHITELIST="$OPTARG"
	     fi
	     ;;
        \?)
             exit 1
             ;;
    esac
done

if [ $TYPE_SET -eq 1 ]; then

	if [ $FILE_SET -eq 0 ]; then
		cat - | eval "$(eval whitelist)" | format
	fi

	if [ $FILE_SET -eq 1 ] && [ -f $FILE ]; then
		cat $FILE | eval "$(eval whitelist)" | format
	fi

else
	echo "Missing option: \`\`-T'' is required''"
	exit 1
fi
