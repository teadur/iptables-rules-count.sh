#!/bin/bash
## Author : Quach Chi Cuong
## Last updated : 09/2016
## Description : 
## - iptables controls five different tables: filter, nat, mangle, raw and security.
## - Shell script will show how many active iptables rule-lines on Linux server which use netfilter core-firewall.
##


### Variable Settings ###
TMP_FILE="/tmp/iptables-rule-count.tmp.txt"




if [ "$2" = "ipv6" ]; then
	BINARY=ip6tables
	TMP_FILE="/tmp/ip6tables-rule-count.tmp.txt"
else
	BINARY=iptables
fi





#################################
####### Function progress #######


## Count number of chains in table filter
cal_rule_table_filter()
{
	echo ""
	echo "+++++++++++++++++++++++++++++++++++++++"
	echo "+ Table 'filter' of $BINARY firewall +"
	echo "+++++++++++++++++++++++++++++++++++++++"
	echo ""
	$BINARY -nvL -t filter | grep "^Chain" | awk '{print $2}' 2> /dev/null 1>> ${TMP_FILE}.filter-chains
	SUM_RULE_FILTER=0
	while read CHAIN
	do
		NUM_IPT_FILTER_CHAIN=$($BINARY -nvL ${CHAIN} -t filter | grep -Ev "^Chain|^pkts|^\ pkts" | wc -l)
		echo "-- Chain ${CHAIN} : ${NUM_IPT_FILTER_CHAIN}    (rules)"
		SUM_RULE_FILTER=$((SUM_RULE_FILTER+${NUM_IPT_FILTER_CHAIN}))
	done < ${TMP_FILE}.filter-chains
	echo "---| Sum of amount CHAINS in table 'filter' : $(cat ${TMP_FILE}.filter-chains | wc -l)    (chains)"
	echo "---| Sum of amount RULES in table 'filter' : ${SUM_RULE_FILTER}    (rules)"
	echo ""
}

## Count number of chains in table nat
cal_rule_table_nat()
{
	echo ""
	echo "++++++++++++++++++++++++++++++++++++"
	echo "+ Table 'nat' of $BINARY firewall +"
	echo "++++++++++++++++++++++++++++++++++++"
	echo ""
	$BINARY -nvL -t nat | grep "^Chain" | awk '{print $2}' 2> /dev/null 1>> ${TMP_FILE}.nat-chains
	SUM_RULE_NAT=0
	while read CHAIN
	do
		NUM_IPT_NAT_CHAIN=$($BINARY -nvL ${CHAIN} -t nat | grep -Ev "^Chain|^pkts|^\ pkts" | wc -l)
		echo "-- Chain ${CHAIN} : ${NUM_IPT_NAT_CHAIN}    (rules)"
		SUM_RULE_NAT=$((SUM_RULE_NAT+${NUM_IPT_NAT_CHAIN}))
	done < ${TMP_FILE}.nat-chains
	echo "---| Sum of amount CHAINS in table 'nat' : $(cat ${TMP_FILE}.nat-chains | wc -l)    (chains)"
	echo "---| Sum of amount RULES in table 'nat' : ${SUM_RULE_NAT}    (rules)"
	echo ""
}

## Count number of chains in table mangle
cal_rule_table_mangle()
{
	echo ""
	echo "+++++++++++++++++++++++++++++++++++++++"
	echo "+ Table 'mangle' of $BINARY firewall +"
	echo "+++++++++++++++++++++++++++++++++++++++"
	echo ""
	$BINARY -nvL -t mangle | grep "^Chain" | awk '{print $2}' 2> /dev/null 1>> ${TMP_FILE}.mangle-chains
	
	SUM_RULE_MANGLE=0
	while read CHAIN
	do
		NUM_IPT_MANGLE_CHAIN=$($BINARY -nvL ${CHAIN} -t mangle | grep -Ev "^Chain|^pkts|^\ pkts" | wc -l)
		echo "-- Chain ${CHAIN} : ${NUM_IPT_MANGLE_CHAIN}    (rules)"
		SUM_RULE_MANGLE=$((SUM_RULE_MANGLE+${NUM_IPT_MANGLE_CHAIN}))
	done < ${TMP_FILE}.mangle-chains
	echo "---| Sum of amount CHAINS in table 'mangle' : $(cat ${TMP_FILE}.mangle-chains | wc -l)    (chains)"
	echo "---| Sum of amount RULES in table 'mangle' : ${SUM_RULE_MANGLE}    (rules)"
	echo ""
}

## Count number of chains in table raw
cal_rule_table_raw()
{
	echo ""
	echo "++++++++++++++++++++++++++++++++++++"
	echo "+ Table 'raw' of $BINARY firewall +"
	echo "++++++++++++++++++++++++++++++++++++"
	echo ""
	$BINARY -nvL -t raw | grep "^Chain" | awk '{print $2}' 2> /dev/null 1>> ${TMP_FILE}.raw-chains
	
	SUM_RULE_RAW=0
	while read CHAIN
	do
		NUM_IPT_RAW_CHAIN=$($BINARY -nvL ${CHAIN} -t raw | grep -Ev "^Chain|^pkts|^\ pkts" | wc -l)
		echo "-- Chain ${CHAIN} : ${NUM_IPT_RAW_CHAIN}    (rules)"
		SUM_RULE_RAW=$((SUM_RULE_RAW+${NUM_IPT_RAW_CHAIN}))
	done < ${TMP_FILE}.raw-chains
	echo "---| Sum of amount CHAINS in table 'raw' : $(cat ${TMP_FILE}.raw-chains | wc -l)    (chains)"
	echo "---| Sum of amount RULES in table 'raw' : ${SUM_RULE_RAW}    (rules)"
	echo ""
}

## Count number of chains in table security
cal_rule_table_security()
{
	echo ""
	echo "+++++++++++++++++++++++++++++++++++++++++"
	echo "+ Table 'security' of $BINARY firewall +"
	echo "+++++++++++++++++++++++++++++++++++++++++"
	echo ""
	$BINARY -nvL -t security | grep "^Chain" | awk '{print $2}' 2> /dev/null 1>> ${TMP_FILE}.security-chains
	
	SUM_RULE_SECURITY=0
	while read CHAIN
	do
		NUM_IPT_SECURITY_CHAIN=$($BINARY -nvL ${CHAIN} -t security | grep -Ev "^Chain|^pkts|^\ pkts" | wc -l)
		echo "-- Chain ${CHAIN} : ${NUM_IPT_SECURITY_CHAIN}    (rules)"
		SUM_RULE_SECURITY=$((SUM_RULE_SECURITY+${NUM_IPT_SECURITY_CHAIN}))
	done < ${TMP_FILE}.security-chains
	echo "---| Sum of amount CHAINS in table 'security' : $(cat ${TMP_FILE}.security-chains | wc -l)    (chains)"
	echo "---| Sum of amount RULES in table 'security' : ${SUM_RULE_SECURITY}    (rules)"
	echo ""
}

cal_rule_all()
{

	$BINARY -nvL -t filter 2> /dev/null 1>> ${TMP_FILE}
	$BINARY -nvL -t nat 2> /dev/null 1>> ${TMP_FILE}
	$BINARY -nvL -t mangle 2> /dev/null 1>> ${TMP_FILE}
	$BINARY -nvL -t raw 2> /dev/null 1>> ${TMP_FILE}
	$BINARY -nvL -t security 2> /dev/null 1>> ${TMP_FILE}


	## Count active iptables rule line ##
	grep -v "^$" ${TMP_FILE} > ${TMP_FILE}.2
	rm -f ${TMP_FILE}
	mv ${TMP_FILE}.2 ${TMP_FILE}

	## Print sum of active iptables rule-lines
	NUM_IPT_RULE=$(cat ${TMP_FILE} | grep -Ev "^Chain|^\pkts|^\ pkts" | wc -l)
	NUM_IPT_CHAIN=$(cat ${TMP_FILE} | grep "^Chain" | wc -l)

    ## For NRPE count totals and omit output
    if [ -n "$1" ]; then
        NUM_IPT_TOTAL=$(($NUM_IPT_RULE + $NUM_IPT_CHAIN))
        echo "Rules:$NUM_IPT_RULE Chains:$NUM_IPT_CHAIN Total:$NUM_IPT_TOTAL"
    else
	    echo ""
	    echo "++++++++++++++++++++++++++++++++++++++++++++"
	    echo "+ Summary information of $BINARY firewall +"
	    echo "++++++++++++++++++++++++++++++++++++++++++++"
	    echo ""
	    echo "---| Sum of current $BINARY chains : ${NUM_IPT_CHAIN}   (chains)" 
	    echo "---| Sum of active $BINARY rules : ${NUM_IPT_RULE}    (rules)"
	    echo ""
    fi
}

## Delete file temporary ##
delete_tmp_file()
{
	if [ -f ${TMP_FILE} ];then
	    	rm -f ${TMP_FILE}
	fi

	if [ -f ${TMP_FILE}.filter-chains ];then
	    	rm -f ${TMP_FILE}.filter-chains
	fi

	if [ -f ${TMP_FILE}.nat-chains ];then
	    	rm -f ${TMP_FILE}.nat-chains
	fi

	if [ -f ${TMP_FILE}.mangle-chains ];then
	    	rm -f ${TMP_FILE}.mangle-chains
	fi

	if [ -f ${TMP_FILE}.raw-chains ];then
	    	rm -f ${TMP_FILE}.raw-chains
	fi

	if [ -f ${TMP_FILE}.security-chains ];then
	    	rm -f ${TMP_FILE}.security-chains
	fi
}


####################
## Main Functions ##

if [ -z ${TMP_FILE} ];then
	TMP_FILE="/tmp/iptables-rule-count.tmp.txt"
fi


delete_tmp_file
## For NRPE only count totals and omit all other output
if [ "$1" = "nrpe" ]; then
    cal_rule_all nrpe
else
    cal_rule_all
    cal_rule_table_filter
    cal_rule_table_nat
    cal_rule_table_mangle
    cal_rule_table_raw
    cal_rule_table_security
fi
    delete_tmp_file
exit 0
