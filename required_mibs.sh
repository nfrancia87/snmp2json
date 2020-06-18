#!/bin/bash
# GET MIBS FROM CIRCITOR
Path=/usr/share/snmp/mibs/
input_file=(http://www.circitor.fr/Mibs/Mib/C/CISCO-VTP-MIB.mib http://www.circitor.fr/Mibs/Mib/I/IF-MIB.mib http://www.circitor.fr/Mibs/Mib/S/SNMPv2-MIB.mib http://www.circitor.fr/Mibs/Mib/I/IP-MIB.mib http://www.circitor.fr/Mibs/Mib/R/RFC1213-MIB.mib http://www.circitor.fr/Mibs/Mib/B/BGP4-MIB.mib http://www.circitor.fr/Mibs/Mib/O/OSPF-MIB.mib)
cd $Path
for i in ${input_file[@]}; do wget $i; done
