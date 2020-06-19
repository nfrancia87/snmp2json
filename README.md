# snmp2json 
Extract snmp raw data from any net element and get a json formatted output, through a flask exposed API.  
As part of my entertainment during COVID-19 lockdown, I set out myself to code a POC application that would get SNMP raw data from network
devices and output json format. 

# Network_Neo4J_DB 
I incrementally added specific OIDs supports, exposed an API to get this information to wrap things up by packing it in a docker containerized app. The Json output may then be consumed through the api into a database to store and  graph this information. This information is then correlated across network devices, visualizing it as a relationship graph between ARP tables, IPs, Network. You will End up having 
a graph database of your entire network. 

This simplifies and exposes many network miss configurations, path related problems as well as security risk.  It 
also enables to have a real-time network repository as well general information about IP usage, Vlan numbering, etc.

#OID
    "Snmpv2Mib"
    "IfMib"
    "CiscoVtpMib"
    "IpMib"
    "Rfc1213Mib"
    "Bgp4Mib"
    "OspfMib"
    
Get Neo4J_DB https://neo4j.com/developer/python/
Setup your VirtualEnv so you won't affect other projects you might have. https://help.dreamhost.com/hc/es/articles/115000695551-Instalar-y-usar-virtualenv-con-Python-3
Get Docker-Compose, from your "venv" run "pip install docker-compose"
Then run it "docker-compose up --build -d"
Test it from any browser!
