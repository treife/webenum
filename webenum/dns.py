import select
import socket
import struct
import ipaddress


class Header:
    SIZE = 12

    def __init__(self):
        self.buf = bytes()
        self.id = 0
        self.qr = False
        self.opcode = 0
        self.aa = False
        self.tc = False
        self.rd = False
        self.ra = False
        self.z = 0
        self.rcode = 0
        self.qdcount = 0
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0

    @classmethod
    def from_buf(cls, data: bytes):
        hdr = cls()
        hdr.id, flags, hdr.qdcount, hdr.ancount, hdr.nscount, hdr.arcount = struct.unpack('!HHHHHH', data)
        hdr.qr = (flags & (1 << 15)) >> 15
        hdr.opcode = (flags & (0xf << 11)) >> 11
        hdr.aa = (flags & (1 << 10)) >> 10
        hdr.tc = (flags & (1 << 9)) >> 9
        hdr.rd = (flags & (1 << 8)) >> 8
        hdr.ra = (flags & (1 << 7)) >> 7
        hdr.z = (flags & (7 << 4)) >> 4
        hdr.rcode = flags & 0xf
        return hdr

    @classmethod
    def from_values(cls, id_: int, qr: bool, opcode: int, aa: bool, tc: bool, rd: bool, ra: bool, z: int, rcode: int,
                    qdcount: int, ancount: int, nscount: int, arcount: int):
        hdr = cls()
        hdr.id = id_
        hdr.qr = qr
        hdr.opcode = opcode
        hdr.aa = aa
        hdr.tc = tc
        hdr.rd = rd
        hdr.ra = ra
        hdr.z = z
        hdr.rcode = rcode
        hdr.qdcount = qdcount
        hdr.ancount = ancount
        hdr.nscount = nscount
        hdr.arcount = arcount
        return hdr

    def serialize(self):
        flags = 0
        flags |= self.rcode & 0xf
        flags |= (self.z & 7) << 4
        flags |= self.ra << 7
        flags |= self.rd << 8
        flags |= self.tc << 9
        flags |= self.aa << 10
        flags |= (self.opcode & 0xf) << 11
        flags |= self.qr << 15
        buf = struct.pack('!HHHHHH', self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount)
        return buf


class NotFoundError(Exception):
    def __init__(self, domain):
        super().__init__(f'No such name "{domain}"')


def query(domain: str, dns_addr: str, queried_record: str = 'A', timeout_sec: int = 5) -> list[tuple[str, str]]:
    req = bytearray()
    req_id = 1
    req.extend(Header.from_values(
        id_=req_id,
        qr=False, opcode=0, aa=False, tc=False, rd=True, ra=False, z=0, rcode=0,
        qdcount=1, ancount=0, nscount=0, arcount=0
    ).serialize())

    question = bytearray()
    subdomains = domain.split('.')
    for sub in subdomains:
        assert len(sub) <= 255
        question.extend(struct.pack('B', len(sub)))
        question.extend(sub.encode('utf-8'))
    # Terminating segment with 0 length
    question.append(0)
    req.extend(question)
    if queried_record == 'AAAA':
        req.append(0x00)
        req.append(0x1c)
    elif queried_record == 'A':
        req.append(0x00)
        req.append(0x01)
    elif queried_record == 'NS':
        req.append(0x00)
        req.append(0x02)
    else:
        raise ValueError(f'queried_record must either be A, AAAA or NS (got "{queried_record}")')
    # Class: INT
    req.append(0x00)
    req.append(0x01)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    s.sendto(req, (dns_addr, 53))

    ready = select.select([s], [], [], timeout_sec)
    if ready[0]:
        resp = s.recv(4096)
    else:
        raise RuntimeError('Request timed out')

    resp_hdr = Header.from_buf(resp[:Header.SIZE])
    if resp_hdr.rcode == 0x03:
        raise NotFoundError(domain)
    if resp_hdr.ancount == 0:
        return []
    payload = resp[Header.SIZE:]
    i = 0

    def read_domain_name(buf: bytes = payload, pos: int = -1, advance_i: bool = True) -> str:
        nonlocal i
        read_i = i if pos == -1 else pos
        if buf[read_i] & 0xc0 == 0xc0:
            # https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
            name_i = (struct.unpack("!H", buf[read_i:read_i+2]))[0] & 0x3fff
            read_i += 2
            if advance_i:
                i = read_i
            return read_domain_name(buf=resp, pos=name_i, advance_i=False)
        else:
            length = buf[read_i]; read_i += 1
            if length == 0:
                if advance_i:
                    i = read_i
                return ''
            name = buf[read_i:read_i+length].decode('ascii'); read_i += length
            if advance_i:
                i = read_i
            next_name = read_domain_name(buf=buf, pos=read_i, advance_i=advance_i)
            if next_name:
                return name + '.' + next_name
            return name
    # Skip queries
    for question_i in range(resp_hdr.qdcount):
        read_domain_name()
    i += 4
    # Parse answers
    results = []
    for rec_i in range(resp_hdr.ancount):
        dn = read_domain_name()
        type_ = struct.unpack('!H', payload[i:i+2])[0]; i += 2
        class_ = struct.unpack('!H', payload[i:i+2])[0]; i += 2
        ttl_ = struct.unpack('!I', payload[i:i+4])[0]; i += 4
        data_len = struct.unpack('!H', payload[i:i+2])[0]; i += 2
        data = payload[i:i+data_len]; i += data_len
        if type_ == 0x01:  # A - IPv4
            host = '%i.%i.%i.%i' % (data[0], data[1], data[2], data[3])
            results.append((dn, host))
        elif type_ == 0x02:  # NS
            ns = read_domain_name(buf=data, pos=0, advance_i=False)
            results.append((dn, ns))
        elif type_ == 0x1c:  # AAAA - IPv6
            ipv6 = []
            for idx in range(0, 16, 2):
                ipv6.append(('%02x' % data[idx]) + ('%02x' % data[idx+1]))
            full_ipv6 = ':'.join(ipv6)
            abbrev = ipaddress.ip_address(full_ipv6).compressed
            results.append((dn, abbrev))

    return results
