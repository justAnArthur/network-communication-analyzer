import os
import sys
import dpkt

from utils import *

# Replace this with your protocol file path
protocols_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'protocols.yaml')

output = {'name': 'PKS2023/24', 'packets': []}
protocols = []


def getProtocol(type, hex_type):
    """
    :param type: The type of protocol (e.g., 'eth', 'ip', 'tcp')
    :param hex_type: The hexadecimal representation of the protocol type
    :return: The resulting protocol or None if it is unknown
    """

    key = int.from_bytes(hex_type, 'big')
    if key in protocols[type]:
        return protocols[type][key]
    # print('UNK protocol: ', ''.join('{:02x}'.format(b) for b in hex_type))
    return None


def write(data):
    """
    :param data: A dictionary containing packet data and communication data.
    :return: None

    This method takes in a dictionary of packet data and communication data and performs some modifications to the
    data structure. It removes certain fields from the dictionary to clean up the data. Then, it prints the modified
    dictionary to a YAML file with the same name as the input PCAP file, but with a .yaml extension instead. And also
    manages output for valid schema.
    """

    from ruamel.yaml import YAML
    yaml = YAML()

    # if 'packets' in data:
    #     for packet in data['packets']:
    #         if 'flags' in packet:
    #             del packet['flags']
    #         if packet.get('ether_type') == 'ARP':
    #             del packet['arp_request_ip']
    #             del packet['arp_ocode']
    #         if 'arp_response_mac' in packet:
    #             del packet['arp_response_mac']
    #         if 'tftp_type' in packet:
    #             del packet['tftp_type']
    #         if 'tftp_blksize' in packet:
    #             del packet['tftp_blksize']
    # if packet.get('ether_type') == 'ARP':
    #     del packet['arp_request_ip']
    #     del packet['arp_response_ip']
    # if 'arp_response_mac' in packet:
    #     del packet['arp_response_mac']

    # if 'complete_comms' in data:
    #     for communication in data['complete_comms']:
    #         if 'src_comm' in communication:
    #             del communication['src_comm']
    #             del communication['dst_comm']
    #         if 'blksize' in communication:
    #             del communication['blksize']
    #         if 'packets' in communication:
    #             for packet in communication['packets']:
    #                 if 'flags' in packet:
    #                     del packet['flags']
    #                 if 'tftp_type' in packet:
    #                     del packet['tftp_type']
    #                 if 'tftp_blksize' in packet:
    #                     del packet['tftp_blksize']
    # if packet.get('ether_type') == 'ARP':
    #     del packet['arp_request_ip']
    #     del packet['arp_response_ip']
    # if 'arp_response_mac' in packet:
    #     del packet['arp_response_mac']

    # if 'partial_comms' in data:
    #     for communication in data['partial_comms']:
    #         if 'src_comm' in communication:
    #             del communication['src_comm']
    #             del communication['dst_comm']
    #             if 'blksize' in communication:
    #                 del communication['blksize']
    #         if 'packets' in communication:
    #             for packet in communication['packets']:
    #                 if 'flags' in packet:
    #                     del packet['flags']
    #                 if 'tftp_type' in packet:
    #                     del packet['tftp_type']
    #                 if 'tftp_blksize' in packet:
    #                     del packet['tftp_blksize']
    # if packet.get('ether_type') == 'ARP':
    #     del packet['arp_request_ip']
    #     del packet['arp_response_ip']
    # if 'arp_response_mac' in packet:
    #     del packet['arp_response_mac']

    print('Printing to file...')
    with open(data.get('pcap_name').split('.')[0] + '.yaml', 'w') as output_file:
        yaml.dump(data, output_file)

    # yaml.dump(data, sys.stdout)


def read_protocols_file(file_path):
    global protocols
    from ruamel.yaml import YAML
    yaml = YAML()
    with open(file_path, 'r') as file:
        protocols = yaml.load(file)


def read_pcap_file(file_path):
    """
    :param file_path: The path to the pcap file to be read.
    :return: None

    Read a pcap file located at `file_path` and processes each packet in the file.
    The processed packets are stored in the `output` variable defined elsewhere.
    """

    with (open(file_path, 'rb') as file):
        pcap = dpkt.pcap.Reader(file)

        index = 0
        for timestamp, buf in pcap:

            index += 1
            hex_frame = buf
            # noinspection PyDictCreation
            packet = {}

            packet['frame_number'] = index
            packet['len_frame_pcap'] = len(buf)
            packet['len_frame_medium'] = packet['len_frame_pcap'] + 4

            if packet['len_frame_medium'] < 60:
                packet['len_frame_medium'] = 60

            packet['src_mac'] = mac_format(buf[0:6])
            packet['dst_mac'] = mac_format(buf[6:12])

            ether_length = buf[12:14]

            # check on ISL and cut if
            if ' '.join(f'{b:02X}' for b in buf[0:5]) == '01 00 0C 00 00':
                buf = buf[26:]

            if ether_length >= b'\x06x00':
                packet['frame_type'] = 'ETHERNET II'
                packet['ether_type'] = getProtocol('ether_type', ether_length)
                buf = buf[14:]
            else:
                if ether_length <= b'\x05\xDC':
                    packet['frame_type'] = 'IEEE 802.3 LLC'

                    if buf[14:15] == 0xAA and buf[15:16] == 0xAA:
                        packet['sap'] = 'SNAP'
                        packet['pid'] = getProtocol('pid', buf[20:22])
                    else:
                        packet['sap'] = getProtocol('sap', buf[14:15])

                else:
                    packet['frame_type'] = 'IEEE 802.3 RAW'

            if 'ether_type' in packet:
                match packet['ether_type']:
                    case 'IPv4':
                        packet['src_ip'] = ipv4_format(buf[12:16])
                        packet['dst_ip'] = ipv4_format(buf[16:20])

                        packet['flags_mf'] = str(bin(int.from_bytes(buf[6:7], 'big'))[2:]).zfill(8)[:3][2] == '1'

                        if packet['flags_mf']:
                            packet['id'] = int.from_bytes(buf[4:6], 'big')

                        packet['frag_offset'] = int(bin((buf[6] << 8 | buf[7]) & 0x1FFF), 2)  # todo is null

                        # if is fragmented (not start) don't continue parsing
                        if packet['frag_offset'] > 0:
                            packet['id'] = int.from_bytes(buf[4:6], 'big')
                            packet['hexa_frame'] = hex_format(hex_frame)
                            output['packets'].append(packet)
                            continue

                        packet['protocol'] = getProtocol('ip', buf[9:10])

                        buf = buf[(buf[0] & 0x0F) * 4:]
                    case 'IPv6':
                        packet['src_ip'] = ipv6_format(buf[8:])
                        packet['dst_ip'] = ipv6_format(buf[24:])

                        packet['protocol'] = getProtocol('ip', buf[6:7])
                        buf = buf[40:]
                    case 'ARP':
                        packet['arp_response_ip'] = ipv4_format(buf[14:18])
                        packet['arp_request_ip'] = ipv4_format(buf[24:28])

                        if int.from_bytes(buf[6:8], 'big') == 1:
                            packet['arp_ocode'] = 'REQUEST'
                        else:
                            packet['arp_ocode'] = 'REPLY'
                            packet['arp_response_mac'] = mac_format(buf[8:14])

                        buf = buf[28:]

            if packet.get('frag_offset', 0) > 0:
                # is fragmented (header is not readable)
                continue

            if 'protocol' in packet:
                match packet['protocol']:
                    case 'TCP':
                        packet['src_port'] = int.from_bytes(buf[0:2], 'big')
                        packet['dst_port'] = int.from_bytes(buf[2:4], 'big')

                        packet['flags'] = str(bin(int.from_bytes(buf[13:14], 'big'))[2:][-7:]).zfill(6)

                        packet['app_protocol'] = getProtocol('tcp', buf[2:4]) or getProtocol('tcp', buf[0:2])

                        # find a protocol by sender_port
                        if packet['app_protocol'] is None:
                            for _packet in output['packets']:
                                if _packet.get('protocol') == 'UDP' and _packet['src_port'] == packet['dst_port']:
                                    packet['app_protocol'] = _packet['app_protocol']

                        buf = buf[buf[12] * 4:]
                    case 'UDP':
                        packet['src_port'] = int.from_bytes(buf[0:2], 'big')
                        packet['dst_port'] = int.from_bytes(buf[2:4], 'big')

                        packet['app_protocol'] = getProtocol('udp', buf[2:4]) or getProtocol('udp', buf[0:2])

                        # find a protocol by sender_port
                        if packet['app_protocol'] is None:
                            for _packet in output['packets']:
                                if _packet.get('protocol') == 'UDP' and _packet['src_port'] == packet['dst_port']:
                                    packet['app_protocol'] = _packet['app_protocol']

                        buf = buf[8:]
                    case 'ICMP':
                        icmp_type = {
                            0: 'Echo REPLY',
                            3: 'Destination Unreachable',
                            4: 'Source Quench',
                            5: 'Redirect',
                            8: 'Echo REQUEST',
                            9: 'Router Advertisement',
                            10: 'Router Solicitation',
                            11: 'TTL Exceeded',
                            12: 'Parameter Problem',
                            13: 'Timestamp Request',
                            14: 'Timestamp Reply',
                            17: 'Address Mask Request',
                            18: 'Address Mask Reply'
                        }
                        packet['icmp_type'] = icmp_type.get(int.from_bytes(buf[0:1], 'big'), 'UNK')
                        packet['icmp_id'] = int.from_bytes(buf[4:6], 'big')
                        packet['icmp_seq'] = int.from_bytes(buf[6:8], 'big')

            if 'app_protocol' in packet:
                match packet['app_protocol']:
                    case 'TFTP':
                        tftp_type = {
                            1: 'Read REQUEST',
                            2: 'Write REQUEST',
                            3: 'DATA',
                            4: 'ACK',
                            6: 'OPTION Acknowledgement'
                        }
                        packet['tftp_type'] = tftp_type.get(int.from_bytes(buf[0:2], 'big'))

                        if 'REQUEST' in str(packet['tftp_type']):
                            try:
                                array = buf[2:].decode('ascii', 'ignore').split('\x00')
                                packet['tftp_blksize'] = int(array[array.index('blksize') + 1])
                            except ValueError:
                                'made by justAnArthur :)'

            packet['hexa_frame'] = hex_format(hex_frame)
            output['packets'].append(packet)


def ipv4_statistics():
    """
    This method calculates statistics for IPv4 packets based on the provided input.

    :return: None
    """

    ipv4_packets = list(filter(lambda _packet: _packet.get('ether_type') == 'IPv4', output['packets']))
    count = {}
    if len(ipv4_packets) > 0:
        for packet in ipv4_packets:
            count[str(packet['src_ip'])] = count.get(str(packet['src_ip']), 0) + 1

        output['ipv4_senders'] = []
        for ip in list(count.keys()):
            output['ipv4_senders'].append({
                'node': ip,
                'number_of_sent_packets': count[ip]
            })

        max_sent_packets = max(count.values())

        # Get all the IPs that sent that many packets
        max_send_packets_by = [ip for ip, packets_sent in count.items() if packets_sent == max_sent_packets]

        output['max_send_packets_by'] = max_send_packets_by


def calcFragmented():
    ipv4_packets = list(filter(lambda _packet: _packet.get('ether_type') == 'IPv4', output['packets']))
    count = 0
    if len(ipv4_packets) > 0:
        for packet in ipv4_packets:
            if packet['flags_mf'] == True or packet['frag_offset'] > 0:
                count += 1

    output['count_of_fragmented_packets'] = count


def handle_protocol(protocol):
    """
    Handle communication for different protocols.

    :param protocol: The protocol to handle. Valid values are 'HTTP', 'HTTPS', 'TELNET', 'SSH', 'FTP_control',
    'FTP_data', 'ARP', 'TFTP', 'ICMP'.
    :return: None

    The handle_protocol(protocol) function takes a protocol name as an input and processes network communications (
    packet data) based on the given protocol. The function works with packet data stored in the dictionary output[
    'packets']. Below is a brief summary of the functions performed for each protocol: HTTP, HTTPS, TELNET, SSH,
    FTP_control, FTP_data: The function iterates over the stored packets, filtering those that match the provided
    protocol and have TCP as the transport layer protocol. It keeps track of unique connections by creating a key
    composed of source and destination IPs and ports. It also monitors the SYN and FIN flags in the TCP header to
    track the start and end of connections. ARP: The function filters out ARP packets, collating requests and replies
    based on requester IP. TFTP: The function filters TFTP packets and creates unique connections based on the given
    key (a combination of source and destination IPs). Special case handling is done for port 69, the default port
    for TFTP. ICMP: The function filters ICMP packets, creating connections using a combination of source and
    destination IPs and the ICMP id of the packets. In each case, the function separates the full and partial
    communications. Full communications are the exchanges where an actual start and end of a conversation are
    detected, whereas partial tracks the exchanges that lack either start or end. For unimplemented protocols,
    the function simply prints 'not implemented protocol'. After processing the packets, the function removes the
    packets and other unneeded data from the output dictionary and writes the output. From the code, it seems like
    the write(output) function is not defined in this block. It is expected to be included in the utils imported from
    utils module. Remember, this processing and interpretation heavily depends on the packet structure and naming
    conventions the rest of the code using, as details like those are not visible from the provided code block.
    """

    output['complete_comms'] = []
    output['partial_comms'] = []

    match protocol:
        case 'HTTP' | 'HTTPS' | 'TELNET' | 'SSH' | 'FTP_control' | 'FTP_data':
            communications = {}
            closed_communication_watcher = {}

            for packet in output['packets']:
                if protocol == packet.get('app_protocol') and packet.get('protocol') == 'TCP':
                    key = ('-'.join(ip for ip in sorted([packet['src_ip'], packet['dst_ip']]))
                           + '-'.join(str(port) for port in sorted([packet['src_port'], packet['dst_port']])))

                    if key not in communications:
                        communications[key] = {'_number_comm': 1}

                    number_comm = communications[key]['_number_comm']

                    if number_comm not in communications[key]:
                        communications[key][number_comm] = {
                            'src_comm': key.split('-')[0],
                            'dst_comm': key.split('-')[1],
                            'packets': []
                        }

                    communications[key][number_comm]['packets'].append(packet)

                    # tcp_flags = ['URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']

                    # if SYN and FIN was already - new communication
                    if packet['flags'][4] == '1' and closed_communication_watcher.get(key) == 1:
                        communications[key]['_number_comm'] += 1
                        del closed_communication_watcher[key]

                    # mark that connection is closing
                    if packet['flags'][5] == '1' or packet['flags'][3] == '1':
                        closed_communication_watcher[key] = 1

            for communication_within_ips_and_ports in communications.values():
                del communication_within_ips_and_ports['_number_comm']
                for communication in communication_within_ips_and_ports.values():
                    category = 'complete_comms' if (
                            any(packet['flags'][4] == '1' for packet in communication['packets'])
                            and (any(packet['flags'][5] == '1' or packet['flags'][3] == '1' for packet in
                                     communication['packets']))
                    ) else 'partial_comms'
                    output[category].append({
                        'number_comm': output[category][-1]['number_comm'] + 1 if len(output[category]) > 0 else 1,
                        **communication
                    })
        case 'ARP':  # cannot find a packet with REPLY operation in wireshark
            communications = {}

            for packet in output['packets']:
                if 'ARP' == packet.get('ether_type'):
                    key = '-'.join(ip for ip in sorted([str(packet['arp_response_ip']), str(packet['arp_request_ip'])]))

                    if key not in communications:
                        communications[key] = {}

                    if packet['arp_ocode'] not in communications[key]:
                        communications[key][packet['arp_ocode']] = []

                    communications[key][packet['arp_ocode']].append(packet)

            for communication in communications.values():
                category = 'complete_comms' if len(communication.keys()) > 1 else 'partial_comms'
                output[category].append({
                    'number_comm': output[category][-1]['number_comm'] + 1 if len(output[category]) > 0 else 1,
                    'packets': sorted(communication.get('REQUEST', []) + communication.get('REPLY', []),
                                      key=lambda comm: comm['frame_number'])
                })
        case 'TFTP':
            communications = {}

            for packet in output['packets']:
                if packet.get('app_protocol') == 'TFTP':
                    key = '-'.join(ip for ip in sorted([str(packet['src_ip']), str(packet['dst_ip'])]))

                    if packet['src_port'] == 69 or packet['dst_port'] == 69:
                        _key = key + '-' + str(packet['dst_port'] if packet['src_port'] == 69 else packet['src_port'])

                        if _key not in communications:
                            communications[_key] = {'_number_comm': -1}

                        communications[_key]['_number_comm'] += 1
                        number_comm = communications[_key]['_number_comm']

                        communications[_key][number_comm] = {
                            'src_comm': packet['src_ip'],
                            'dst_comm': packet['dst_ip'],
                            'blksize': packet['tftp_blksize'],
                            'packets': [],
                        }

                        communications[_key][number_comm]['packets'].append(packet)
                        continue

                    number_comm = communications[_key]['_number_comm']

                    if (key + '-' + str(packet['src_port'])) in communications:
                        communications[key + '-' + str(packet['src_port'])][number_comm]['packets'].append(packet)
                        continue

                    if (key + '-' + str(packet['dst_port'])) in communications:
                        communications[key + '-' + str(packet['dst_port'])][number_comm]['packets'].append(packet)
                        continue

                    if len(output['partial_comms']) < 1:
                        output['partial_comms'].append({
                            'number_comm': 1,
                            'packets': []
                        })

                    output['partial_comms'][-1]['packets'].append(packet)

            for communication_within_ips_and_ports in communications.values():
                del communication_within_ips_and_ports['_number_comm']
                for communication in communication_within_ips_and_ports.values():
                    category = 'complete_comms' if (
                            len(communication['packets']) >= 4
                            and 'ACK' in str(communication['packets'][-1]['tftp_type'])
                            and
                            list(filter(lambda _packet: _packet.get('tftp_type') == 'DATA', communication['packets']))
                            [-1]['len_frame_pcap'] < communication['blksize']
                    ) else 'partial_comms'
                    output[category].append({
                        'number_comm': output[category][-1]['number_comm'] + 1 if len(output[category]) > 0 else 1,
                        **communication
                    })
        case 'ICMP':
            communications = {}

            for packet in output['packets']:
                if packet.get('protocol') == 'ICMP':
                    key = '-'.join(ip for ip in sorted([packet['src_ip'], packet['dst_ip']]))

                    if key + str(packet['icmp_id']) not in communications:
                        communications[key + str(packet['icmp_id'])] = {
                            'src_comm': key.split('-')[0],
                            'dst_comm': key.split('-')[1],
                            'packets': []
                        }

                    communications[key + str(packet['icmp_id'])]['packets'].append(packet)

                if packet.get('frag_offset', -1) > 0:
                    for communication in communications.values():
                        packet_by_id = next(
                            (_packet for _packet in communication['packets'] if
                             _packet.get('id') == packet['id']),
                            None)

                        if packet_by_id is not None:
                            communications[key + str(packet_by_id['icmp_id'])]['packets'].append(packet)

            for key, communication in communications.items():
                category = 'complete_comms' if (
                        any('REQUEST' in str(packet.get('icmp_type')) for packet in communication['packets'])
                        and any('REPLY' in str(packet.get('icmp_type')) for packet in communication['packets'])
                ) else 'partial_comms'
                output[category].append({
                    'number_comm': output[category][-1]['number_comm'] + 1 if len(output[category]) > 0 else 1,
                    **communication
                })
        case _:
            print('not implemented protocol')
            return

    # todo remove
    del output['packets']
    del output['ipv4_senders']
    del output['max_send_packets_by']

    write(output)


def handle_argv(argv):
    """
    :param argv: A list of command line arguments.
    :return: None

    The function `handle_argv` takes in a list of command line arguments `argv` and performs the following tasks:
    1. Check if the number of arguments is less than 2 or if the second argument is '-h'. If either condition is true, it prints usage instructions and available options.
    2. Calculates the length of the arguments, excluding the program name.
    3. If the length is less than 1, it prints an error message and returns.
    4. Set the 'pcap_name' key in the `output` dictionary to the value of the second argument.
    5. Attempts to read the protocol file and pcap file using the specified paths, and handles any exceptions that may occur.
    6. Call the `ipv4_statistics` function.
    7. If there is only one argument, it writes the `output` and returns.
    8. If there are three arguments and the second argument is '-p' or '--protocol', and the third argument is not None, it sets the 'filter_name' key in the `output` dictionary to the value of the third argument and calls the `handle_protocol` function.
    9. If none of the conditions above match, it prints usage instructions and available options.
    """

    if len(argv) < 2 or argv[1] == '-h':
        print('use:\n   python main.py <path_to_file> [options]')
        print('options:\n  -p, --protocol [HTTP|HTTPS|TELNET|SSH|FTP_session|FTP_data]')

    length = len(argv) - 1  # the length of parameters only
    if length < 1:
        print('not specified file to parse')
        return

    output['pcap_name'] = argv[1]
    try:
        read_protocols_file(protocols_file_path)
        read_pcap_file(argv[1])
    except FileNotFoundError as e:
        print(f'file cannot be found by specified path {e}')
        return
    except PermissionError:
        print("The program does not have the necessary permissions to open the file.")
        return
    except Exception as e:
        print(f"An error occurred: {e}")
        return
    ipv4_statistics()
    calcFragmented()

    if length == 1:
        write(output)
        # save to file
        return

    if length == 3 and (argv[2] == '-p' or argv[2] == '--protocol') and argv[3] is not None:
        output['filter_name'] = argv[3]
        handle_protocol(argv[3])
        return

    print('use:\n   python main.py <path_to_file> [options]')
    print('options:\n  -p, --protocol [HTTP|HTTPS|TELNET|SSH|FTP_session|FTP_data]')


handle_argv(sys.argv)
