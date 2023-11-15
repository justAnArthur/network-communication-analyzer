def mac_format(hex_in_bytes):
    return ':'.join(format(x, '02x') for x in hex_in_bytes)


def ipv4_format(hex_in_bytes):
    return ".".join(map(str, hex_in_bytes))


def ipv6_format(hex_in_bytes):
    return ':'.join(format(int.from_bytes(hex_in_bytes[i:i + 2], 'big'), '04x') for i in range(0, 16, 2))


def hex_format(hex_in_bytes):
    from ruamel.yaml.scalarstring import LiteralScalarString
    return LiteralScalarString(
        '\n'.join(' '.join(f'{b:02X}' for b in hex_in_bytes[i:i + 16]) for i in range(0, len(hex_in_bytes), 16)) + '\n')
