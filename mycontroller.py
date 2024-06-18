import p4runtime_sh.shell as sh
import argparse
import threading
from scapy.all import Ether, IP, TCP, UDP, ICMP, BOOTP, DHCP
import queue

FLOODING = 256

class Controller:
    def __init__(self, device_id, grpc_addr):
        self.device_id   = device_id
        self.grpc_addr   = grpc_addr
        self.packet_in_q = queue.Queue()
        self.port_to_ip = {
            1: '192.168.0.1',
            2: '192.168.0.2'
        }
        self.tuple_to_port = {}
        self.port_table    = {}
        self.nat_pool      = {}
        self.running = 1
        self._packet_in_thread = None

        for i in range(5001, 6025):
            self.port_table[i] = 0

    def log(self, *args):
        print(f'[{self.grpc_addr}]:', *args)

    def setUp(self):
        sh.setup(
            device_id=self.device_id,
            grpc_addr=self.grpc_addr,
            election_id=(0, 1),
            config=sh.FwdPipeConfig('build/firewall.p4.p4info.txt', 'build/firewall.json')
        )
        packetin = sh.PacketIn()
        def _handle_packet_in():
            while self.running:
                for pkt in packetin.sniff(timeout=0.01):
                    self.packet_in_q.put(pkt)
        self._packet_in_thread = threading.Thread(target=_handle_packet_in)
        self._packet_in_thread.start()
        self.log('setup success!')

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(1)
        te.match['hdr.ipv4.dstAddr'] = "192.168.0.0/24"
        te.action['dir'] = str(0)
        te.insert()

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(1)
        te.match['hdr.ipv4.dstAddr'] = "10.0.2.0/24"
        te.action['dir'] = str(1)
        te.insert()

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(1)
        te.match['hdr.ipv4.dstAddr'] = "10.0.3.0/24"
        te.action['dir'] = str(1)
        te.insert()

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(2)
        te.match['hdr.ipv4.dstAddr'] = "192.168.0.0/24"
        te.action['dir'] = str(0)
        te.insert()

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(2)
        te.match['hdr.ipv4.dstAddr'] = "10.0.2.0/24"
        te.action['dir'] = str(1)
        te.insert()

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(2)
        te.match['hdr.ipv4.dstAddr'] = "10.0.3.0/24"
        te.action['dir'] = str(1)
        te.insert()

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(3)
        te.match['hdr.ipv4.dstAddr'] = "10.0.1.0/24"
        te.action['dir'] = str(2)
        te.insert()

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(3)
        te.match['hdr.ipv4.dstAddr'] = "10.0.3.0/24"
        te.action['dir'] = str(3)
        te.insert()

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(4)
        te.match['hdr.ipv4.dstAddr'] = "10.0.1.0/24"
        te.action['dir'] = str(2)
        te.insert()

        te = sh.TableEntry('MyIngress.direction_table')(action="MyIngress.set_direction")
        te.match['standard_metadata.ingress_port'] = str(4)
        te.match['hdr.ipv4.dstAddr'] = "10.0.2.0/24"
        te.action['dir'] = str(3)
        te.insert()

        te = sh.TableEntry('MyIngress.ipv4_lpm')(action="MyIngress.ipv4_forward")
        te.match['hdr.ipv4.dstAddr'] = "10.0.3.0/24"
        te.action['dstAddr'] = "08:00:00:00:03:00"
        te.action['port']    = str(4)
        te.insert()

        te = sh.TableEntry('MyIngress.ipv4_lpm')(action="MyIngress.ipv4_forward")
        te.match['hdr.ipv4.dstAddr'] = "10.0.2.0/24"
        te.action['dstAddr'] = "08:00:00:00:02:00"
        te.action['port']    = str(3)
        te.insert()

        te = sh.TableEntry('MyIngress.ipv4_lpm')(action="MyIngress.ipv4_forward")
        te.match['hdr.ipv4.dstAddr'] = "192.168.0.1/32"
        te.action['dstAddr'] = "08:00:00:00:01:11"
        te.action['port']    = str(1)
        te.insert()

        te = sh.TableEntry('MyIngress.ipv4_lpm')(action="MyIngress.ipv4_forward")
        te.match['hdr.ipv4.dstAddr'] = "192.168.0.2/32"
        te.action['dstAddr'] = "08:00:00:00:01:12"
        te.action['port']    = str(2)
        te.insert()


    def dhcpoffer(self, pkt, port):
        self.log('dhcpoffer called', pkt, port)
        ether = Ether(src='08:00:00:00:01:00', dst=pkt.getlayer(Ether).src)
        ip = IP(src='192.168.0.254', dst='255.255.255.255')
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2, 
            xid=pkt.getlayer(BOOTP).xid,
            yiaddr=self.port_to_ip[port],
            giaddr=pkt.getlayer(BOOTP).giaddr,
            chaddr=pkt.getlayer(BOOTP).chaddr
        )
        dhcp = DHCP(options=[
            ('message-type', 'offer'),
            ('lease_time', 300),
            ('server_id', '192.168.0.254'),
            ('subnet_mask', '255.255.255.0'),
            ('router', '192.168.0.254'),
            'end'
        ])
        
        print((ether / ip / udp / bootp / dhcp).show(dump=True))
        
        return ether / ip / udp / bootp / dhcp

    def dhcpack(self, pkt, port):
        ether = Ether(src='08:00:00:00:01:00', dst=pkt.getlayer(Ether).src)
        ip = IP(src='192.168.0.254', dst='255.255.255.255')
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2, 
            xid=pkt.getlayer(BOOTP).xid,
            yiaddr=self.port_to_ip[port],
            giaddr=pkt.getlayer(BOOTP).giaddr,
            chaddr=pkt.getlayer(BOOTP).chaddr
        )
        dhcp = DHCP(options=[
            ('message-type', 'ack'),
            ('lease_time', 300),
            ('server_id', '192.168.0.254'),
            ('subnet_mask', '255.255.255.0'),
            ('router', '192.168.0.254'),
            'end'
        ])

        print((ether / ip / udp / bootp / dhcp).show(dump=True))
        
        return ether / ip / udp / bootp / dhcp

    def run(self):
        while self.running:
            try:
                pktin = self.packet_in_q.get()
                payload = pktin.packet.payload
                packet_out = sh.PacketOut()
                packet_out.metadata['mes_type'] = '0'
                pkt = Ether(_pkt=payload)

                src_mac = pkt.getlayer(Ether).src
                dst_mac = pkt.getlayer(Ether).dst
                port = int.from_bytes(pktin.packet.metadata[1].value, 'big')
                self.log(src_mac, dst_mac, port)

                if pkt.haslayer(IP):
                    src_ip   = pkt.getlayer(IP).src
                    dst_ip   = pkt.getlayer(IP).dst
                    protocol = pkt[IP].proto

                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                if pkt.haslayer(UDP):
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport

                self.log('packet in!!')
                if pkt.haslayer(DHCP):
                    self.log('dhcp packet!!')

                    print(pkt.show())
                    
                    if ('message-type', 1) in pkt.getlayer(DHCP).options:
                        packet_out.payload = bytes(self.dhcpoffer(pkt, port))
                    elif ('message-type', 3) in pkt.getlayer(DHCP).options:
                        packet_out.payload = bytes(self.dhcpack(pkt, port))
                    packet_out.metadata['egress_port'] = str(port)
                
                elif pkt.haslayer(TCP) or pkt.haslayer(UDP):
                    self.log('tcp/udp packet')

                    for i in range(5001, 6025):
                        if self.port_table[i] == 0:
                            port_snat = i
                            self.port_table[i] = 1
                            self.tuple_to_port[(src_ip, src_port, dst_ip, dst_port, protocol)] = port_snat
                            break

                    te = sh.TableEntry('MyIngress.inside_nat')(action="MyIngress.snat")
                    te.match['hdr.ipv4.srcAddr']  = str(src_ip)
                    te.match['hdr.port.srcPort']  = str(src_port)
                    te.match['hdr.ipv4.dstAddr']  = str(dst_ip)
                    te.match['hdr.port.dstPort']  = str(dst_port)
                    te.match['hdr.ipv4.protocol'] = str(protocol)
                    te.action['nat_ipaddr'] = "10.0.1.1"
                    te.action['port_num1']  = str(port_snat)
                    te.insert()

                    te = sh.TableEntry('MyIngress.outside_nat')(action="MyIngress.dnat")
                    te.match['hdr.ipv4.srcAddr']  = str(dst_ip)
                    te.match['hdr.port.srcPort']  = str(dst_port)
                    te.match['hdr.ipv4.dstAddr']  = "10.0.1.1"
                    te.match['hdr.port.dstPort']  = str(port_snat)
                    te.match['hdr.ipv4.protocol'] = str(protocol)
                    te.action['nat_ipaddr'] = str(src_ip)
                    te.action['port_num2']  = str(src_port)
                    te.insert()

                    packet_out.payload = payload
                    packet_out.metadata['ip_addr'] = "10.0.1.1"
                    packet_out.metadata['port_num'] = str(port_snat)


                if pkt.haslayer(ICMP):
                    self.log('icmp packet')

                    te = sh.TableEntry('MyIngress.icmp_snat')(action="MyIngress.nat_ping")
                    te.match['hdr.ipv4.srcAddr']      = str(src_ip)
                    te.match['hdr.ipv4.dstAddr']      = str(dst_ip)
                    te.match['hdr.icmp_echo.id'] = str(pkt[ICMP].id)
                    te.action['nat_ipaddr'] = "10.0.1.1"
                    te.insert()

                    te = sh.TableEntry('MyIngress.icmp_dnat')(action="MyIngress.nat_pong")
                    te.match['hdr.ipv4.srcAddr']      = str(dst_ip)
                    te.match['hdr.ipv4.dstAddr']      = "10.0.1.1"
                    te.match['hdr.icmp_echo.id'] = str(pkt[ICMP].id)
                    te.action['nat_ipaddr'] = str(src_ip)
                    te.insert()
                
                packet_out.send()

            except KeyboardInterrupt:
                self.running = 0


    def cleanUp(self):
        self.log('clean up')
        self.running = 0
        self._packet_in_thread.join()
        sh.teardown()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('device_id', type=int)
    parser.add_argument('grpc_addr', type=str)
    args = parser.parse_args()

    test_case = Controller(args.device_id, args.grpc_addr)
    test_case.setUp()
    test_case.run()
    test_case.cleanUp()


# h3:  iperf -s -i 1 -p 9999
# h11: iperf -c 10.0.3.3 -i 1 -p 9999 -t 10 -B 192.168.0.1:7777