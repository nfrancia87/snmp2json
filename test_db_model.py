"""/usr/bin/env Python3"""
import requests
import json
import os
import ipaddress
import re
from py2neo import Graph, Node, Relationship, NodeMatcher
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#Line to connect to a Neo4j
#Make sure to modify the codeline both to secure it and passing the right parameters 
graph = Graph('/db/data/', host='ADD_DB_IP_NETWORK', username='neo4j', password='neo4j')
matcher = NodeMatcher(graph)

class RouterNode():
    """docstring for NetElement"""
    def __init__(self, NetElement, community):
        self.NetElement = NetElement
        self.community = community

    def api_call(self):
        url = 'http://ADD_YOUR_SNMP2JSON_API_IP:5005/api/v1/device/'+ self.NetElement +'/community/'+ self.community
        timeout = 5
        r =  requests.get(url)
        self.snmp2json = r.json()

    def find_router(self, hostname):
        """docstring Function to find existing routers """
        router = matcher.match("Router", hostname = hostname).first()
        return router

    def new_router_node(self):
        self.api_call()
        if 'message' not in self.snmp2json:
            self.hostname = self.snmp2json[self.NetElement][u'DevInfo'][u'hostname']
            self.dev_info = self.snmp2json[self.NetElement][u'DevInfo'][u'description']
            self.vlans = self.snmp2json[self.NetElement][u'L2Domain'][u'Vlans']
            router = Node('Router', hostname = self.hostname, devinfo = self.dev_info, vlans = list(self.vlans))
            router.__primarylabel__ = "Router"
            router.__primarykey__ = "hostname"
            if not self.find_router(self.hostname):
                graph.create(router)
            self.new_interfaces_node(router)
            self.new_arp_neighbor_rel(router)
            self.new_network_node(router)
            self.dynamic_neighbors(router)

        
    def find_interface(self, uniqueness, int_id = "int_id"):
        if int_id !="":
            result = matcher.match('Interface').where(int_id = int_id, UNIQUENESS = uniqueness).first()
            return result 
        else:
            result = matcher.match('Interface', UNIQUENESS = uniqueness).first()
            return result

    
    def new_interfaces_node(self, router):
        self.interfaces = self.snmp2json[self.NetElement][u'Interfaces']
        for i in self.interfaces:
            int_id = i.replace('Int_Id:', '')
            for j in self.interfaces[i]:
                if j == 'ifPhysAddress':
                    if_mac_address = self.interfaces[i][j]
                    if_uniqueness = if_mac_address + '_' + self.hostname + '_' + int_id
                elif j == 'ifDescr':
                    if_name = self.interfaces[i][j]
                elif j == 'ifOperStatus':
                    if_op_status = self.interfaces[i][j]
                elif j == 'ifAdminStatus':
                    if_adm_status = self.interfaces[i][j]
                elif j == 'ifSpeed':
                    if_speed = self.interfaces[i][j]
                elif j == 'ifMtu':
                    if_mtu = self.interfaces[i][j]
            interface = Node('Interface',  name = if_name, int_id = int_id, MAC = if_mac_address, UNIQUENESS= if_uniqueness,
                                AdmStatus = if_adm_status, OpStatus = if_op_status, Speed = if_speed, MTU = if_mtu)
            interface.__primarylabel__ = "Interface"
            interface.__primarykey__ = "UNIQUENESS"
            BELONGS_TO = Relationship.type('BELONGS_TO')
            rel_router_int = graph.merge(BELONGS_TO(interface,router))
        self.new_ip_addr_node()           

    def find_ip_addr(self, ip_addr):
        result = matcher.match('Ip_address', address = ip_addr).first()
        return result

    def new_ip_addr_node(self):
        ip_addresses = self.snmp2json[self.NetElement][u'L3Domain'][u'IPs']
        for i in ip_addresses:
            int_id = i
            for j in ip_addresses[i]:
                if not '127.0.0.' in j:
                    if not self.find_ip_addr(j):
                        ip = Node('Ip_address',int_id = int_id, status = 'Active', address = j)
                        ip.__primarylabel__ = "Ip_address"
                        ip.__primarykey__ = "address"
                        graph.create(ip)
                    query = '''MATCH (i:Interface)-[:BELONGS_TO]->(r:Router), (ip:Ip_address) 
                               WHERE ((r.hostname = {hostname} and i.int_id = {int_id}) and ip.address = {address})
                               CREATE UNIQUE (ip)-[:CONFIGURED_IN]->(i) '''
                    rel_ip_int = graph.run(query, hostname = self.hostname, int_id = int_id, address = j )

    def new_arp_neighbor_rel(self, Router):
        arp_neighbor = self.snmp2json[self.NetElement][u'L3Domain'][u'ARP_Neighbors']
        for i in arp_neighbor:
            int_id = i
            if ('Int_Id:' + int_id) in self.interfaces:
                int_bw = self.interfaces['Int_Id:' + int_id]['ifSpeed']
                int_name = self.interfaces['Int_Id:' + int_id]['ifDescr']
                for j in arp_neighbor[i]:
                    if not '127.0.0.' in j:
                        ip_addr = j[0]
                        mac_addr = j[1]
                        neigh_info = j[2]
                        ip = Node('Ip_address', status = 'Active', address = ip_addr)
                        ip.__primarylabel__ = "Ip_address"
                        ip.__primarykey__ = "address"
                        if not self.find_ip_addr(ip_addr):
                            graph.create(ip)
                        query =  ''' MATCH (i:Interface)-[:BELONGS_TO]->(r:Router), (ip:Ip_address)
                                     WHERE (r.hostname = {hostname} and i.int_id = {int_id}) and ip.address = {ip_addr}
                                     CREATE UNIQUE (i)-[:SEEN_BY_ARP]->(ip) '''
                        rel_arp_int_ip = graph.run(query, hostname = self.hostname, 
                                                   int_id = int_id, ip_addr = ip_addr)
                        if (('0:50:56' or '0:c:29' or '0:25:b3') in mac_addr):
                            server = Node('Server', MAC = mac_addr, property = 'VmWare_VM')
                            server.__primarylabel__ = "Server"
                            server.__primarykey__ = "MAC"
                            CONFIGURED_IN = Relationship.type('CONFIGURED_IN')
                            rel_ip_server = graph.merge(CONFIGURED_IN(ip,server))

                        elif ('0:9:f:' in mac_addr):
                            firewall = Node('Firewall', MAC = mac_addr, property = 'FortiNet')
                            firewall.__primarylabel__ = 'Firewall'
                            firewall.__primarykey__ = 'MAC'
                            CONFIGURED_IN = Relationship.type('CONFIGURED_IN')
                            rel_ip_server = graph.merge(CONFIGURED_IN(ip,firewall))
                            self.arp_relationship(Router, firewall, int_name, int_bw)
                        
                        elif (('5c:f3:fc' or '0:15:17') in mac_addr):
                            if re.search('5c:f3:fc', mac_addr):
                                server = Node('Server', MAC = mac_addr, property = 'IBM_SERVER')
                            else:
                                server = Node('Server', MAC = mac_addr, property = 'INTEL_SERVER')
                            server.__primarylabel__ = "Server"
                            server.__primarykey__ = "MAC"
                            CONFIGURED_IN = Relationship.type('CONFIGURED_IN')
                            rel_ip_server = graph.merge(CONFIGURED_IN(ip,server))

                        elif 'message' not in neigh_info:
                            hostname = neigh_info[u'hostname']
                            dev_info = neigh_info[u'description']
                            print (hostname, self.hostname, self.NetElement)
                            arp_router = Node('Router', hostname = hostname, devinfo = dev_info)
                            arp_router.__primarylabel__ = "Router"
                            arp_router.__primarykey__ = "hostname"
                            self.arp_relationship(Router, arp_router, int_name, int_bw, hostname)

    def arp_relationship(self, Router, arp_neighbor, int_name, int_bw, hostname = 'hostname'):
        ARP_NEIGHBORS = Relationship.type("ARP_NEIGHBORS")
        try:
            rel_arp_router = graph.merge(ARP_NEIGHBORS(Router,arp_neighbor, int_name = int_name,int_bw = int_bw))
        except IndexError:
            print ("Error in ", hostname)
            pass

    def find_network(self, network):
        result = matcher.match('Network', ip_range = network).first()
        return result

    def new_network_node(self, router):
        self.local_networks = self.snmp2json[self.NetElement][u'L3Domain'][u'Local_Nets']
        for i in self.local_networks:
            if i != '127.0.0.0/8':
                ip_range = i
                network = Node('Network', ip_range = ip_range)
                network.__primarylabel__ = 'Network'
                network.__primarykey__ = 'ip_range'
                rel_net_router = Relationship(network, 'LOCAL_ROUTE_TO', router)
                if not self.find_network(ip_range):
                    graph.create(rel_net_router)
                else:
                    query = '''MATCH (n:Network), (r:Router)
                               WHERE n.ip_range = {ip_range} and r.hostname = {hostname}
                               CREATE UNIQUE (n)-[:LOCAL_ROUTE_TO]-> (r)'''
                    rel_net_router = graph.run(query, ip_range = ip_range, hostname = self.hostname)
                net_hosts = ipaddress.ip_network(ip_range).hosts()
                for host in net_hosts:
                    query = '''MATCH (ip:Ip_address), (m:Network)
                               WHERE (ip.address = {ip_addr} and ip.status = 'Active') and m.ip_range = {net_range}
                               CREATE UNIQUE (ip)-[:MEMBER_OF_NETWORK]->(m)'''
                    rel_ip_network = graph.run(query, ip_addr = str(host), net_range = ip_range)
    
    def dynamic_neighbors(self, router):
        ospf_info = self.snmp2json[self.NetElement][u'L3Domain'][u'OSPF_INFO']
        bgp_info = self.snmp2json[self.NetElement][u'L3Domain'][u'BGP_INFO']
        if ospf_info['Router_Id']:
            router['Router_Id'] = ospf_info['Router_Id']
            graph.push(router)
            ospf_areas = ospf_info['Areas']
            ospf_neigh = ospf_info['Neighbors']
            for area in ospf_areas:
                area_id = ospf_areas[area]['AreaId']
                area_status = ospf_areas[area]['AreaStatus']
                area_auth_type = ospf_areas[area]['AuthType']
                ospf_area_node = Node('Ospf_Area', id = area_id, status = area_status, auth = area_auth_type)
                ospf_area_node.__primarylabel__ = 'Ospf_Area'
                ospf_area_node.__primarykey__ = 'id'
                PART_OF = Relationship.type('PART_OF')
                rel_router_int = graph.merge(PART_OF(router,ospf_area_node))
            for neighbor in ospf_neigh:
                neigh_id = ospf_neigh[neighbor]['NbrRtrId']
                neigh_ip = ospf_neigh[neighbor]['NbrIpAddr']
                neigh_state = ospf_neigh[neighbor]['NbrState']
                ip = Node('Ip_address', status = 'Active', address = neigh_ip)
                ip.__primarylabel__ = "Ip_address"
                ip.__primarykey__ = "address"
                OSPF_NEIGHBOR = Relationship.type('OSPF_NEIGHBOR')
                rel_ospf_router = graph.merge(OSPF_NEIGHBOR(router,ip, state = neigh_state, neigh_rt_id = neigh_id))
        if bgp_info['LocalAs']:
            router['LocalAs'] = bgp_info['LocalAs']
            graph.push(router)
            bgp_peers = bgp_info['Peers']
            for peer in bgp_peers:
                peer_local_add = bgp_peers[peer]['PeerLocalAddr']
                peer_id = bgp_peers[peer]['PeerIdentifier']
                peer_as = bgp_peers[peer]['PeerRemoteAs']
                peer_address = bgp_peers[peer]['PeerRemoteAddr']
                peer_state = bgp_peers[peer]['PeerState']
                ip = Node('Ip_address', status = 'Active', address = peer_address)
                ip.__primarylabel__ = "Ip_address"
                ip.__primarykey__ = "address"
                BGP_PEER = Relationship.type('BGP_PEER')
                rel_bgp_router = graph.merge(BGP_PEER(router, ip, state = peer_state, peer_rt_id = peer_id))

    def find_ip_int_router_rel(self, ipaddress):
        query = '''MATCH (r:Router)<-[:BELONGS_TO]-(i:Interface)<-[:CONFIGURED_IN]-(ip:Ip_address)
                   WHERE ip.address = {ip_address}
                   RETURN r.hostname, ip.address as address'''
        result = graph.run(query, ip_address = ipaddress )
        for i in result:
            if i['address'] == ipaddress:
                return True
        return False
                

#A few lines of code to test the script

routers = 'ADD_A_NETWORK/ADD_NETWORK_MASK'
ip_hosts = ipaddress.ip_network(routers).hosts()
for ip in ip_hosts:
    ip_str = str(ip)
    router = RouterNode( ip_str, 'ADD_YOUR_COMMUNITY')
    scanned_router = router.find_ip_int_router_rel(ip_str)
    if not scanned_router:
        router.new_router_node()
    else:
        print("Ip ",ip, "ya encontrada en ", scanned_router)
