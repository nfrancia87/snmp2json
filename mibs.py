mibs={
  "mibs": {
    "BasicData": [
      "SNMPv2-MIB::sysName",
      "SNMPv2-MIB::sysDescr",
      "SNMPv2-MIB::sysLocation",
      "SNMPv2-MIB::sysUpTime"
    ],
    "IfMib": [
      "IF-MIB::ifEntry"
    ],
    "IfEntryElements": {
      "Primary": [
        "ifDescr",
        "ifType",
        "ifMtu",
        "ifSpeed",
        "ifPhysAddress",
        "ifAdminStatus",
        "ifOperStatus"
      ],
      "Seconday": [
        "ifInOctets.",
        "ifInUcastPkts.",
        "ifInNUcastPkts.",
        "ifInDiscards.",
        "ifInErrors.",
        "ifInUnknownProtos.",
        "ifOutOctets.",
        "ifOutUcastPkts.",
        "ifOutNUcastPkts.",
        "ifOutDiscards.",
        "ifDescr.",
        "ifOutQLen.",
        "ifSpecific.",
        "ifLastChange."
      ]
    },
    "CiscoVtpMib": [
      "CISCO-VTP-MIB::managementDomainLocalMode",
      "CISCO-VTP-MIB::vtpVlanState",
      "CISCO-VTP-MIB::vtpVlanName"
    ],
    "IpMib": [
      "IP-MIB::ipAdEntIfIndex",
      "IP-MIB::ipAdEntNetMask",
      "IP-MIB::ipNetToMediaPhysAddress"
    ],
    "Rfc1213Mib": [
      "RFC1213-MIB::ipRouteNextHop",
      "RFC1213-MIB::ipRouteMask",
      "RFC1213-MIB::ipRouteProto",
      "RFC1213-MIB::ipRouteIfIndex"
    ],
    "Bgp4Mib": [
      "BGP4-MIB::bgpLocalAs",
      "BGP4-MIB::bgpPeerLocalAddr",
      "BGP4-MIB::bgpPeerRemoteAs",
      "BGP4-MIB::bgpPeerIdentifier",
      "BGP4-MIB::bgpPeerState",
      "BGP4-MIB::bgpPeerRemoteAddr"
    ],
    "OspfMib": [
      "OSPF-MIB::ospfRouterId",
      "OSPF-MIB::ospfNbrRtrId",
      "OSPF-MIB::ospfNbrIpAddr",
      "OSPF-MIB::ospfNbrState",
      "OSPF-MIB::ospfAreaId",
      "OSPF-MIB::ospfAuthType",
      "OSPF-MIB::ospfAreaStatus"
    ]
  }
}
