#!/bin/bash

# functions
usage()
{
cat <<EOF

Prepares a reputation list for Bro's Intel Framework.
Designed to work with mal-dnssearch.

	Add lines to local.bro or similar to load the Intel Framework:
	@load frameworks/intel/seen
	@load frameworks/intel/do_notice

	redef Intel::read_files += {
	    "/opt/bro/share/bro/site/mandiant.intel",
	    "/opt/bro/share/bro/site/malhosts.intel",
	    };

     Options:
        -T <type>	Intel::Type '(ip/dns)' e.g. \`\`-T ip''
	-f <file>	Read parsed list from file (if option is ommited, use stdin)
	-i <location>	Location seen in Bro (def: null)
	-n <boolean>	Call Notice Framework on matches, 'true/false' (def: false)
	-s <name>	Name for data source (def: mal-dnssearch)

Usage: $0 -T <type> [ -f <logfile> ] [ -s <name> ] [ -n <boolean> ] [ -i <location> ]
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

awk -v type=$TYPE -v source=$SOURCE -v notice=$NOTICE -v if_in=$IF_IN  'BEGIN \
        {
	       	print "#fields\tindicator\tindicator_type\tmeta.source\tmeta.do_notice\tmeta.if_in"
	}
	{
		$2=type; $3=source; $4=notice; $5=if_in;
		print $1"\t"$2"\t"$3"\t"$4"\t"$5;
	}'

}

# Initializations
SOURCE="mal-dnssearch"
NOTICE="F"
IF_IN="-"
ARGC=$#
FILE_SET=0
TYPE_SET=0

argcheck 1

while getopts "hf:i:n:T:s:" OPTION
do
     case $OPTION in
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
	     if [[ "$OPTARG" == ip ]]; then
             	     TYPE=Intel::ADDR
	     elif [[ "$OPTARG" == dns ]]; then
		     TYPE=Intel::DOMAIN
	     else
		     echo "Unknown type!"
                     exit 1
             fi
	     TYPE_SET=1
	     ;;
	 s)
 	     SOURCE="$OPTARG"
  	     ;;
        \?)
             exit 1
             ;;
    esac
done

if [ $TYPE_SET -eq 1 ]; then

	if [ $FILE_SET -eq 0 ]; then
		cat - | format
	fi

	if [ $FILE_SET -eq 1 ] && [ -f $FILE ]; then
		cat $FILE | format
	fi

else
	echo "Missing option: \`\`-T'' is required''"
	exit 1
fi
