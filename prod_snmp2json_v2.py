"""/usr/bin/ Python"""
import json
import shlex, subprocess
import re
from mibs import mibs
from netaddr import IPNetwork


class SnmpObject():
    """docstring for SnmpObject"""
    # pylint: disable=too-many-instance-attributes
    def __init__(self, community, hostname):
        self.community = community
        self.hostname = hostname
        self.snmp_mibs = mibs['mibs']
        self.snmp_data = {}
        self.error_message = {}
        self.process_output = {self.hostname : {'DevInfo' : {}, 'Interfaces' : {},
                                                    'L2Domain' : { 'Vlans' : {}, 'vtp_mode': ''},
                                                    'L3Domain' : {'ARP_Neighbors': {}, 'IPs': {}, 'Local_Nets' : [], 'Routes' : {},
                                                        'BGP_INFO' : { 'LocalAs' : '', 'Peers':{} }, 
                                                        'OSPF_INFO' : {'Router_Id':'','Neighbors':{},'Areas': {} }}}}
    def snmpbulkwalk(self):
        """Function to invoque sys call to snmpbulk data"""
        run = subprocess.getstatusoutput
        timeout = '0.1'
        for mibs in self.snmp_mibs:
            if mibs != 'IfEntryElements':
                for oid in self.snmp_mibs[mibs]:
                    param = (' -O q -v 2c -t ' + timeout +' -c '+ self.community + ' ' + self.hostname + ' ' + oid)
                    command = ('snmpbulkwalk' + param)
                    print(command)
                    status, raw_output = run(command)
                    if (status == 0 and 'No Such' not in raw_output):
                        self.snmp_data[oid] = {}
                        self.snmp_data[oid] = [raw_output]
                    elif 'Unknown host' in raw_output:
                        self.error_message = {"message":"Unknown host " + self.hostname}
                        break
                    elif 'Timeout' in raw_output:
                        self.error_message = {"message":"Timeout from host " + self.hostname}
                        break
                    elif 'Unknown Object Identifier' in raw_output:
                        pass
            if self.error_message:
                break


    def parse_snmpv2_mib(self):
        """Function to parse SNMPv2-MIB"""
        patterns = mibs['mibs']['BasicData']
        for data in self.snmp_data:
            for oid in patterns:
                if re.match(oid, data):
                    for value in self.snmp_data[data]:
                        if re.search('SNMPv2-MIB::sysDescr',value):
                            temp = value.replace('SNMPv2-MIB::sysDescr.0 ', '').split(',')
                            self.process_output[self.hostname]['DevInfo']["description"] = temp
                            break
                        elif re.search('SNMPv2-MIB::sysName', value):
                            aux = value.split(' ')
                            self.process_output[self.hostname]['DevInfo']["hostname"] = aux[1]
                            break
                        elif re.search('SNMPv2-MIB::sysLocation', value):
                            aux = value.split(' ')
                            if aux[1]!="":
                                self.process_output[self.hostname]['DevInfo']["location"] = aux[1]
                            else:
                                self.process_output[self.hostname]['DevInfo']["location"] = "NotSet"
                            break
                        else:
                            aux = value.split(' ')
                            self.process_output[self.hostname]['DevInfo']["Uptime"] = aux[1]

    #Encuentro if_entry. Separo la cadena en sub cadenas formadas por
    #tuples (oid valor). Encuentro los indices # Separo el tuple
    #Me quedo con el indice. Extraigo la informamcion de cada indice

    def parse_if_mib(self):
        """Function to parse IF-MIB"""
        int_index = []
        patterns = mibs['mibs']['IfMib']
        for data in self.snmp_data:
            for oid in patterns:
                if re.match(oid, data):
                    for value in self.snmp_data[data]:
                        data = value.split('\n')
                        for data_1 in data:
                            if  re.findall("ifIndex", data_1):
                                aux = data_1.split(' ')
                                int_index.append(aux[1])
                            else:
                                break
                        self.parse_int_index_info(data, int_index)
                        break

    #Para cada indice itero, creo el vector de patrones a buscar por indice.
    #Busco el vector de patrones en los datos obtenidos. Hago match entre
    #los datosobtenidos y los valores extraido para cada info

    def parse_int_index_info(self, aux, index):
        """Function to parse IndexInterfaces"""
        if_entry = mibs['mibs']['IfEntryElements']['Primary']
        for int_id in index:
            pattern = []
            int_information_aux = {}
            for items in if_entry:
                pattern.append('IF-MIB::'+ items + '.' + int_id + ' ')
            for j in pattern:
                for value in aux:
                    if re.match(j, value):
                        aux_2 = value.split(' ')
                        int_information_aux[aux_2[0].strip("IF-MIB::").strip('.' + int_id)] = aux_2[1]
                        break
            self.process_output[self.hostname]['Interfaces']['Int_Id:'+ int_id] = int_information_aux

    def parse_ip_mib(self):
        """Function to parse IP-MIB -NeedsOptimization"""
        patterns = mibs['mibs']['IpMib']
        for data in self.snmp_data:
            for oid in patterns:
                if re.match(oid, data):
                    for value in self.snmp_data[data]:
                        if re.search('IP-MIB::ipAdEntIfIndex.', value):
                            aux = value.split('\n')
                            for i in aux:
                                var_tuple = i.replace('IP-MIB::ipAdEntIfIndex.', '').split(' ')
                                try:
                                    self.process_output[self.hostname]['L3Domain']['IPs'][var_tuple[1]].append(var_tuple[0])
                                except KeyError:
                                    self.process_output[self.hostname]['L3Domain']['IPs'][var_tuple[1]] = [var_tuple[0]]
                                    pass
                            break
                        elif re.search('IP-MIB::ipAdEntNetMask.', value):
                            aux = value.split('\n')
                            for i in aux:
                                var_tuple = i.replace('IP-MIB::ipAdEntNetMask.', '').split(' ')
                                if not str(IPNetwork(var_tuple[0] +'/'+ var_tuple[1]).cidr) in self.process_output[self.hostname]['L3Domain']['Local_Nets']:
                                    self.process_output[self.hostname]['L3Domain']['Local_Nets'].append(str(IPNetwork(var_tuple[0] +'/'+ var_tuple[1]).cidr))
                                else:
                                    pass
                            break
                        elif re.search('IP-MIB::ipNetToMediaPhysAddress.', value):
                            aux = value.split('\n')
                            for i in aux:
                                if re.search('IP-MIB::ipNetToMediaPhysAddress.0.127.0', i):
                                    pass
                                else:
                                    var_tuple = i.replace('IP-MIB::ipNetToMediaPhysAddress.', '').split(' ')
                                    tuple_aux = re.sub(r"\.", r',', var_tuple[0]).split(',')
                                    int_id = tuple_aux[0]
                                    if re.match((int_id + "\."'1'"\."), var_tuple[0]):
                                        ip = var_tuple[0].replace((int_id + '.1.'), '')
                                    else:
                                        ip = var_tuple[0].replace((int_id + '.'), '')

                                    #Aqui voy a revisar si la IP recibida por ARP es parte del equipo,
                                    #en caso que NO lo sea, paso a buscar la informacion del vecino y
                                    #devuelvo la informacion como un diccionario

                                    mac = var_tuple[1]
                                    if (('0:50:56' or '0:c:29' or '0:25:b3') in mac):
                                        arp_neigh_community = 'public'
                                    else:
                                        arp_neigh_community = self.community
                                    if int_id in self.process_output[self.hostname]['L3Domain']['IPs']:
                                        if ip not in self.process_output[self.hostname]['L3Domain']['IPs'][int_id]:
                                            arp_neigh_object = SnmpObject(arp_neigh_community, ip)
                                            neig_basic_info = arp_neigh_object.get_basic_snmp_data()
                                            try:
                                                self.process_output[self.hostname]['L3Domain']['ARP_Neighbors'][int_id].append([ip, mac, neig_basic_info])
                                            except KeyError:
                                                self.process_output[self.hostname]['L3Domain']['ARP_Neighbors'][int_id] = [[ip, mac, neig_basic_info]]
                                                pass
                                    elif int_id not in self.process_output[self.hostname]['L3Domain']['IPs']:
                                        arp_neigh_object = SnmpObject(arp_neigh_community, ip)
                                        neig_basic_info = arp_neigh_object.get_basic_snmp_data()
                                        try:
                                            self.process_output[self.hostname]['L3Domain']['ARP_Neighbors'][int_id].append([ip, mac, neig_basic_info])
                                        except KeyError:
                                            self.process_output[self.hostname]['L3Domain']['ARP_Neighbors'][int_id] = [[ip, mac, neig_basic_info]]
                                            pass
                    break

    def parse_cisco_vtp_mib(self):
        """Function to parse CiscoVtpMib"""
        oids = mibs['mibs']['CiscoVtpMib']
        for data in self.snmp_data:
            for oid in oids:
                if re.match(oid, data):
                    for value in self.snmp_data[data]:
                        if re.match('CISCO-VTP-MIB::managementDomainLocalMode.1',value):
                            var_tuple = value.replace(oid + '.1.', '').split(' ')
                            self.process_output[self.hostname]['L2Domain']['vtp_mode'] = var_tuple[1]
                            break
                        elif re.search('CISCO-VTP-MIB::vtp', value):
                            aux = value.split('\n')
                            for i in aux:
                                var_tuple = i.replace(oid + '.1.', '').split(' ')
                                value_2 = oid.replace('CISCO-VTP-MIB::vtp', '')
                                try:
                                    self.process_output[self.hostname]['L2Domain']['Vlans'][var_tuple[0]][ value_2 ] = var_tuple[1]
                                except KeyError:
                                    self.process_output[self.hostname]['L2Domain']['Vlans'][var_tuple[0]] = { value_2 : var_tuple[1]}
                    break

    def parse_ref_1213_mib(self):
        """Function to Parse RFC1213-MIB"""
        oids = mibs['mibs']['Rfc1213Mib']
        for data in self.snmp_data:
            for oid in oids:
                if re.match(oid, data):
                    for value in self.snmp_data[data]:
                        if re.search('RFC1213-MIB::ip', value):
                            aux = value.split('\n')
                            for i in aux:
                                var_tuple = i.replace(oid + '.', '').split(' ')
                                value_2 = oid.replace('RFC1213-MIB::ip', '').strip('.')
                                try:
                                    self.process_output[self.hostname]['L3Domain']['Routes'][var_tuple[0]][ value_2 ] = var_tuple[1]
                                except KeyError:
                                    self.process_output[self.hostname]['L3Domain']['Routes'][var_tuple[0]] =  { value_2 : var_tuple[1]}
                    break

    def parse_bgp4_mib(self):
        """Function to parse BGP4-MIB"""
        oids = mibs['mibs']['Bgp4Mib']
        for data in self.snmp_data:
            for oid in oids:
                if re.match(oid, data):
                    for value in self.snmp_data[data]:
                        if re.search('BGP4-MIB::bgpLocalAs.0', value):
                            self.process_output[self.hostname]['L3Domain']['BGP_INFO']['LocalAs'] = value.replace('BGP4-MIB::bgpLocalAs.0 ', '')
                            break
                        else:
                            if re.search(oid, value):
                                aux = value.split('\n')
                                for i in aux:
                                    var_tuple = i.replace(oid, '').split(' ')
                                    value_2 = oid.replace('BGP4-MIB::bgp', '')
                                    bgp_data = var_tuple [1]
                                    try:
                                        self.process_output[self.hostname]['L3Domain']['BGP_INFO']['Peers'][var_tuple[0]][ value_2] = bgp_data 
                                    except KeyError:
                                        self.process_output[self.hostname]['L3Domain']['BGP_INFO']['Peers'][var_tuple[0]] = { value_2 :  bgp_data }
                                        pass
                    break

    def parse_ospf_mib(self):
        """Function to parse OSPF-MIB"""
        oids = mibs['mibs']['OspfMib']
        for data in self.snmp_data:
            for oid in oids:
                if re.match(oid, data):
                    for value in self.snmp_data[data]:
                        if re.match('OSPF-MIB::ospfRouterId.0', value):
                            self.process_output[self.hostname]['L3Domain']['OSPF_INFO']['Router_Id'] = value.replace('OSPF-MIB::ospfRouterId.0 ', '')
                        else:
                            if re.search(oid, value):
                                aux = value.split('\n')
                                for i in aux:
                                    var_tuple = i.replace(oid + '.', '').split(' ')
                                    key = var_tuple[0]
                                    value_2 = oid.replace('OSPF-MIB::ospf', '').strip('.')
                                    ospf_data = var_tuple[1]
                                    try:
                                        if re.search('ospfNbr', oid):
                                            self.process_output[self.hostname]['L3Domain']['OSPF_INFO']['Neighbors'][key][value_2] = ospf_data
                                        else:
                                            self.process_output[self.hostname]['L3Domain']['OSPF_INFO']['Areas'][key.replace('0.0.0.', 'Area: ')][value_2] = ospf_data
                                    except KeyError:
                                        if re.search('ospfNbr', oid):
                                            self.process_output[self.hostname]['L3Domain']['OSPF_INFO']['Neighbors'][key] = { value_2 :  ospf_data }
                                        else:
                                            self.process_output[self.hostname]['L3Domain']['OSPF_INFO']['Areas'][key.replace('0.0.0.','Area: ')] = { value_2 :  ospf_data }
                                break

    def parse_snmp_data(self):
        """Function to invoque all parsing functions"""
        self.parse_snmpv2_mib()
        self.parse_if_mib()
        self.parse_ip_mib()
        self.parse_cisco_vtp_mib()
        self.parse_ref_1213_mib()
        self.parse_bgp4_mib()
        self.parse_ospf_mib()

    def get_snmp_data(self):
        """Function to extrat SNMP_DATA and get a Json in response"""
        self.snmpbulkwalk()
        if not self.error_message:
            self.parse_snmp_data()
            return self.process_output
        return self.error_message

    def get_basic_snmp_data(self):
        """Function to extrat BasicSNMP data"""
        self.snmpbulkwalk()
        if not self.error_message:
            self.parse_snmpv2_mib()
            return self.process_output[self.hostname]['DevInfo']
        return self.error_message
