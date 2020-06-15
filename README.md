# snmp2json 
Extract snmp raw data from any net element and get a json formatted output, through a flask exposed API.  
As part of my entertainment during COVID-19 lockdown, I set out myself to code a POC application that would get SNMP raw data from network
devices and output json format. 

# Network_Neo4J_DB
I incrementally added specific OIDs supports to extend the functionality of it by exposing an API to get this information to end up
packing this as a docker containerized service. Once I was able to manage snmp 2 json information, I included a database to store and 
graph this information. This way I managed to correlate information across network devices like ARP tables, IPs, Network to end up having 
a graph database of my entire network. This approach simplifies and expose many network miss configurations and path related problems.  It 
also enables to have a real-time network repository as well general information about IP usage, Vlan numbering, etc.

#OID
    "Snmpv2Mib"
    "IfMib"
    "CiscoVtpMib"
    "IpMib"
    "Rfc1213Mib"
    "Bgp4Mib"
    "OspfMib"
