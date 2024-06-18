/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

#define CPU_PORT 255

@controller_header("packet_in")
header packet_in_t {
    bit<7> mes_type;
    bit<9> ingress_port;
}

@controller_header("packet_out")
header packet_out_t {
    bit<7>  mes_type;
    bit<9>  egress_port;
    bit<32> ip_addr;
    bit<16> port_num;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    bit<8>  mes_type;
    bit<8>  mes_code;
    bit<16> checksum;
}

header icmp_echo_t {
    bit<16> id;
    bit<16> seq;
}

header port_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

header tcp_t {
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    bit<7>   mes_type;
    bit<9>   egress_port;
    bit<16>  tcp_len;
    bit<32>  ip_addr;
    bit<16>  port_num;
}

struct headers {
    packet_in_t  packet_in;
    packet_out_t packet_out;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
    icmp_echo_t  icmp_echo;
    port_t       port;
    tcp_t        tcp;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default:  parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        meta.mes_type    = hdr.packet_out.mes_type;
        meta.egress_port = hdr.packet_out.egress_port;
        meta.ip_addr     = hdr.packet_out.ip_addr;
        meta.port_num    = hdr.packet_out.port_num;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            1:  parse_icmp;
            6:  parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition select(hdr.icmp.mes_type) {
            0: parse_icmp_echo;
            8: parse_icmp_echo;
            default: accept;
        }
    }

    state parse_icmp_echo {
        packet.extract(hdr.icmp_echo);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.port);
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.port);
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    bit<2> direction = 3;
    // 0: LAN -> LAN
    // 1: LAN -> WAN
    // 2: WAN -> LAN
    // 3: other

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_direction(bit<2> dir) {
        direction = dir;
    }

    action snat(ip4Addr_t nat_ipaddr, bit<16> port_num1) {
        hdr.ipv4.srcAddr = nat_ipaddr;
        hdr.port.srcPort = (bit<16>)port_num1;
    }

    action dnat(ip4Addr_t nat_ipaddr, bit<16> port_num2) {
        hdr.ipv4.dstAddr = nat_ipaddr;
        hdr.port.dstPort = (bit<16>)port_num2;
    }

    action nat_ping(ip4Addr_t nat_ipaddr) {
        hdr.ipv4.srcAddr = nat_ipaddr;
    }

    action nat_pong(ip4Addr_t nat_ipaddr) {
        hdr.ipv4.dstAddr = nat_ipaddr;
    }

    action send_to_cpu() {
        hdr.packet_in.setValid();

        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.ingress_port    = standard_metadata.ingress_port;
        hdr.packet_in.mes_type        = 0;
    }

    action send_dhcp_to_host(bit<9> host_port) {
        standard_metadata.egress_spec = host_port;
    }

    table direction_table {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_direction;
            NoAction;
        }
        size = 1024;
        default_action = set_direction(3);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table inside_nat {
        key = {
            hdr.ipv4.srcAddr:  exact;
            hdr.port.srcPort:  exact;
            hdr.ipv4.dstAddr:  exact;
            hdr.port.dstPort:  exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            snat;
            drop;
            send_to_cpu;
        }
        size = 1024;
        default_action = send_to_cpu();
    }

    table outside_nat {
        key = {
            hdr.ipv4.srcAddr:  exact;
            hdr.port.srcPort:  exact;
            hdr.ipv4.dstAddr:  exact;
            hdr.port.dstPort:  exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            dnat;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table icmp_snat {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.icmp_echo.id: exact;
        }
        actions = {
            nat_ping;
            drop;
            send_to_cpu;
        }
        size = 1024;
        default_action = send_to_cpu();
    }

    table icmp_dnat {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.icmp_echo.id: exact;
        }
        actions = {
            nat_pong;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && standard_metadata.ingress_port != CPU_PORT){
            direction_table.apply();
            
            // DHCP request from client
            if (hdr.udp.isValid() && hdr.port.srcPort == 68) {
                send_to_cpu();
            }

            // ICMP
            else if (hdr.icmp.isValid() && hdr.icmp_echo.isValid()) {
                if (direction == 1) {
                    icmp_snat.apply();
                }
                else if (direction == 2){
                    icmp_dnat.apply();
                }
            }

            // NAT
            else if (hdr.port.isValid()){
                if (hdr.tcp.isValid()) { 
                    // for checksum
                    meta.tcp_len = hdr.ipv4.totalLen - (bit<16>)(hdr.ipv4.ihl) * 4;
                }

                if (direction == 1) {
                    inside_nat.apply();
                } 
                else if (direction == 2) {
                    outside_nat.apply();
                }
            }
        }
        else if (hdr.packet_out.isValid()) {
            hdr.packet_out.setInvalid();

            // first packet return from controller
            if (hdr.ipv4.isValid() && hdr.port.isValid() && hdr.port.dstPort != 68) {
                snat(meta.ip_addr, meta.port_num);
            }

            else if (hdr.ipv4.isValid() && hdr.icmp_echo.isValid()) {
                nat_ping(meta.ip_addr);
            }

            else if (hdr.ipv4.isValid() && hdr.port.isValid() && hdr.udp.isValid() && hdr.port.dstPort == 68) {
                send_dhcp_to_host(meta.egress_port);
            }
        }

        if (hdr.ipv4.isValid() && !hdr.packet_in.isValid()){
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

        update_checksum_with_payload(
            hdr.tcp.isValid(),
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              8w0,
              hdr.ipv4.protocol,
              meta.tcp_len,
              hdr.port.srcPort,
              hdr.port.dstPort,
              hdr.tcp.seqNo,
              hdr.tcp.ackNo,
              hdr.tcp.dataOffset,
              hdr.tcp.res,
              hdr.tcp.ecn,
              hdr.tcp.ctrl,
              hdr.tcp.window,
              hdr.tcp.urgentPtr },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);
        
        update_checksum_with_payload(
            hdr.udp.isValid(),
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              8w0,
              hdr.ipv4.protocol,
              hdr.udp.length,
              hdr.port.srcPort,
              hdr.port.dstPort,
              hdr.udp.length },
            hdr.udp.checksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
