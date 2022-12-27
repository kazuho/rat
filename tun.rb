require "socket"

class IP
    attr_accessor :bytes, :proto, :src_addr, :dest_addr, :l4_start, :l4

    def initialize(bytes)
        @bytes = bytes
    end

    def _parse()
        bytes = @bytes
        return nil if bytes.length < 20
        return nil if bytes[0].ord != 0x45
        # tos?
        # totlen?
        # ignore identification
        return nil if decode_u16(6) & 0xbfff != 0 # ignore fragments
        # ttl: 8
        @proto = bytes[9].ord
        # checksum 10..11
        @src_addr = bytes[12..15]
        @dest_addr = bytes[16..19]

        @l4_start = 20

        if @proto == UDP::PROTOCOL_ID
            self.l4 = UDP.parse(self)
        elsif @proto == TCP::PROTOCOL_ID
            self.l4 = TCP.parse(self)
        elsif @proto == ICMP::PROTOCOL_ID
            self.l4 = ICMP.parse(self)
        end

        self
    end

    def self.parse(bytes)
        IP.new(bytes)._parse
    end

    def tuple()
        @src_addr + @dest_addr
    end

    def apply()
        bytes = @bytes

        orig_l3_tuple = bytes[12..19]

        # decrement TTL
        bytes[8] = (bytes[8].ord - 1).chr

        bytes[12..15] = @src_addr
        bytes[16..19] = @dest_addr

        bytes[10..11] = "\0\0"
        checksum = IP.checksum(bytes, 0, l4_start)
        encode_u16(10, checksum)

        l4.apply(self, orig_l3_tuple)
    end

    def decode_u16(off)
        @bytes[off .. off + 1].unpack1("n")
    end

    def encode_u16(off, v)
        IP.encode_u16(@bytes, off, v)
    end

    def self.encode_u16(bytes, off, v)
        # this seems faster than pack-then-replace
        bytes[off] = ((v >> 8) & 0xff).chr
        bytes[off + 1] = (v & 0xff).chr
    end

    def self.checksum(bytes, from = nil, len = nil)
        from = 0 if from.nil?
        len = bytes.length - from if len.nil?
        to = from + len - 1

        sum = bytes[from .. to].unpack("n*").sum
        if len % 2 != 0
            sum += bytes[to].ord * 256
        end
        ~((sum >> 16) + sum) & 0xffff
    end

    # fom RFC 3022 4.2
    def self.checksum_adjust(sum, old_bytes, new_bytes)
        sum = ~sum & 0xffff;
        for u16 in old_bytes.unpack("n*")
            sum -= u16;
            if sum <= 0
                sum -= 1
                sum &= 0xffff
            end
        end
        for u16 in new_bytes.unpack("n*")
            sum += u16;
            if sum >= 0x10000
                sum += 1
                sum &= 0xffff
            end
        end
        ~sum & 0xffff
    end

    def self.addr_to_s(addr)
        addr.unpack("C4").join(".")
    end
end

class TCPUDP
    attr_accessor :tuple

    def src_port()
        @tuple[0 .. 1].unpack1("n")
    end

    def src_port=(n)
        IP.encode_u16(@tuple, 0, n)
    end

    def dest_port()
        @tuple[2 .. 3].unpack1("n")
    end

    def dest_port=(n)
        IP.encode_u16(@tuple, 2, n)
    end

    def _parse(packet, min_len)
        bytes = packet.bytes
        off = packet.l4_start

        return nil if bytes.length - off < min_len
        @tuple = packet.bytes[off .. off + 3]

        self
    end

    def _apply(packet, orig_l3_tuple, checksum_offset)
        bytes = packet.bytes
        l4_start = packet.l4_start

        orig_bytes = orig_l3_tuple + bytes[l4_start .. l4_start + 3]
        bytes[l4_start .. l4_start + 3] = @tuple
        new_bytes = packet.tuple + @tuple

        checksum = packet.decode_u16(l4_start + checksum_offset)
        checksum = IP.checksum_adjust(checksum, orig_bytes, new_bytes)
        packet.encode_u16(l4_start + checksum_offset, checksum)
    end
end

class UDP < TCPUDP
    PROTOCOL_ID = 17

    def self.parse(packet)
        UDP.new._parse(packet, 8)
    end

    def apply(packet, orig_l3_tuple)
        _apply(packet, orig_l3_tuple, 6)
    end
end

class TCP < TCPUDP
    PROTOCOL_ID = 6

    def self.parse(packet)
        TCP.new._parse(packet, 20)
    end

    def apply(packet, orig_l3_tuple)
        _apply(packet, orig_l3_tuple, 16)
    end
end

class ICMP
    PROTOCOL_ID = 1

    attr_reader :type, :code, :checksum

    def _parse(packet)
        bytes = packet.bytes
        off = packet.l4_start

        @type = bytes[off].ord
        @code = bytes[off + 1].ord
        @checksum = packet.decode_u16(off + 2)

        self
    end

    def self.parse(packet)
        bytes = packet.bytes
        off = packet.l4_start

        return nil if bytes.length - off < 8

        type = bytes[off].ord
        if type == ICMPDestUnreach::TYPE
            icmp = ICMPDestUnreach.new
        else
            icmp = ICMP.new
        end

        icmp._parse(packet)
    end

    def _apply(packet, orig_l3_tuple)
        # ICMP does not use pseudo headers
    end
end

class ICMPDestUnreach < ICMP
    TYPE = 3

    attr_reader :orig_proto
    attr_accessor :orig_src_addr, :orig_dest_addr, :orig_src_port, :orig_dest_port

    def _parse(packet)
        if super(packet).nil?
            return nil
        end

        @orig_packet = Packet.new(packet.bytes[packet.l4_start + 8 ..])
        if @orig_packet.nil?
            return nil
        end

        if @orig_packet.l4.nil?
            puts "FIXME DestUnreach does not fully contain original L4 header? That's allowed in spec"
            return nil
        end

        @orig_proto = @orig_packet.proto
        @orig_src_addr = @orig_packet.src_addr
        @orig_dest_addr = @orig_packet.dest_addr
        @orig_src_port = @orig_packet.decode_u16(@orig_packet.l4_start)
        @orig_dest_port = @orig_packet.decode_u16(@orig_packet.l4_start + 2)

        self
    end

    def _apply(packet, orig_l3_tuple)
        # update 4 tuple of orig_packet
        @orig_packet.src_addr = @orig_src_addr
        @orig_packet.dest_addr = @orig_dest_addr
        @orig_packet.l4.src_port = @orig_src_port
        @orig_packet.l4.dest_port = @orig_dest_port
        @orig_packet.apply

        # overwrite packet image with orig packet being built
        packet.bytes[packet.l4_start + 8 ..] = @orig_packet.bytes

        # recalculate checksum
        packet.encode_u16(packet.l4_start + 2, 0)
        @checksum = IP.checksum(packet.bytes, packet.l4_start, packet.bytes.length - packet.l4_start)
        packet.encode_u16(packet.l4_start + 2, @checksum)
    end
end

class Tun
    IFF_TUN = 1
    IFF_NO_PI = 0x1000
    TUNSETIFF = 0x400454ca

    def initialize(devname)
        @tundev = open("/dev/net/tun", "r+")

        ifreq = [devname, IFF_TUN | IFF_NO_PI].pack("a" + Socket::IFNAMSIZ.to_s + "s!")
        @tundev.ioctl(TUNSETIFF, ifreq)
    end

    def read()
        bytes = @tundev.sysread(1500)
        return IP.parse(bytes)
    end

    def write(packet)
        @tundev.syswrite(packet.bytes)
    end
end
