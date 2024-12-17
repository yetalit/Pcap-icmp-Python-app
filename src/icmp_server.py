import pcapy as pcap
import psutil
import struct
import threading
import sys
import select
import tty
import termios

class ICMPMessage:
    def __init__(self):
        # Dictionary to store ICMP messages with Type and Code as the key
        self.icmp_messages = {
            0: {
                0: "Echo Reply",
            },
            3: {
                0: "Network Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable",
                3: "Port Unreachable",
                4: "Fragmentation Needed and DF set",
                5: "Source Route Failed",
                6: "Destination Network Unknown",
                7: "Destination Host Unknown",
                8: "Source Host Isolated",
                9: "Communication with Destination Network is Administratively Prohibited",
                10: "Communication with Destination Host is Administratively Prohibited",
                11: "Destination Network Unreachable for ToS",
                12: "Destination Host Unreachable for ToS",
                13: "Communication Administratively Prohibited",
                14: "Host Precedence Violation",
                15: "Precedence Cutoff in Effect"
            },
            4: {
                0: "Source Quench"
            },
            5: {
                0: "Redirect Datagram for the Network",
                1: "Redirect Datagram for the Host",
                2: "Redirect Datagram for the ToS & Network",
                3: "Redirect Datagram for the ToS & Host"
            },
            8: {
                0: "Echo Request",
            },
            9: {
                0: "Router Advertisement"
            },
            10: {
                0: "Router Selection"
            },
                      11: {
                0: "Time to Live Exceeded in Transit",
                1: "Fragment Reassembly Time Exceeded"
            },
            12: {
                0: "Pointer Indicates the Error",
                1: "Missing a Required Option"
            },
            13: {
                0: "Timestamp Request"
            },
            14: {
                0: "Timestamp Reply"
            },
            15: {
                0: "Information Request"
            },
            16: {
                0: "Information Reply"
            },
            17: {
                0: "Address Mask Request"
            },
            18: {
                0: "Address Mask Reply"
            }
        }

    def _get(self, icmp_type, icmp_code):
        try:
            return self.icmp_messages[icmp_type][icmp_code]
        except KeyError:
            return f"ICMP Type {icmp_type} with Code {icmp_code} not found!"

icmp_msg = ICMPMessage()

def get_addresses(interface):
    mac = None
    ip = None
    addrs = psutil.net_if_addrs()
    if interface in addrs:
        for addr in addrs[interface]:
            if addr.family == psutil.AF_LINK and not mac:
                print('MAC:', addr.address)
                mac = addr.address
            if addr.family == 2 and not ip:
                print('IP:', addr.address)
                ip = addr.address
    return ip

device = None
fp = None
try:
    devices = pcap.findalldevs()
    if devices:
        device = devices[0]
        print("A device found:", device)
    else:
        print("No devices found!")
        exit()
    fp = pcap.open_live(device, 65535, True, 1000)
    print(f"Successfully opened {device}")
except pcap.PcapError as e:
    print(f"Error-> {e}")
    exit()

ip_address = get_addresses(device)

def listen():
    def packet_callback(header, packet):
        source_ip = ''
        dest_ip = ''
        for i in range(4):
            source_ip += str(packet[26 + i])
            dest_ip += str(packet[30 + i])
            if i != 3:
                source_ip += '.'
                dest_ip += '.'
        if source_ip == ip_address:
            print('->', icmp_msg._get(packet[34], packet[35]), 'sent to', dest_ip)
        else:
            print('--------------------------------')
            print('Source:', source_ip)
            print('Destination:', dest_ip)
            print('Message:', icmp_msg._get(packet[34], packet[35]))
            print('--------------------------------')

    try:
        fp.setfilter("icmp")
        fp.loop(0, packet_callback)
    except pcap.PcapError as e:
        print(f"Error-> {e}")

_thread = threading.Thread(target=listen, daemon=True)
_thread.start()

class NonBlockingConsole(object):
    def __enter__(self):
        self.old_settings = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
        return self

    def __exit__(self, type, value, traceback):
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)

    def get_data(self):
        if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
            return sys.stdin.read(1)
        return False

with NonBlockingConsole() as nbc:
    i = 0
    while True:
        i += 1
        if nbc.get_data() == '\x7a':
            fp.close()
            break
