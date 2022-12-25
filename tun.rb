require "socket"

class Packet
    attr_accessor :bytes, :l3, :l4, :l4_start

    def initialize(bytes)
        self.bytes = bytes
        self.l3 = IPv4.parse(self)
        if self.l3
            if self.l3.proto == UDP::PROTOCOL_ID
                self.l4 = UDP.parse(self)
            elsif self.l3.proto == TCP::PROTOCOL_ID
                self.l4 = TCP.parse(self)
            end
        end
    end

    def apply()
        orig_l3_tuple = l3._apply(self)
        l4._apply(self, orig_l3_tuple)
    end

    def decode_u16(off)
        return @bytes[off].ord * 256 + @bytes[off + 1].ord
    end

    def encode_u16(off, v)
        @bytes[off] = ((v >> 8) & 0xff).chr
        @bytes[off + 1] = (v & 0xff).chr
    end
end

class IP
    attr_accessor :src_addr, :dest_addr
    attr_reader :checksum, :proto, :ttl

    def self.checksum(bytes, from = nil, len = nil)
        from = 0 if from.nil?
        len = bytes.length - from if len.nil?

        sum = 0
        for i in 0 .. len / 2 - 1 do
            sum += bytes[from + i * 2].ord * 256 + bytes[from + i * 2 + 1].ord
        end
        if len % 2 != 0
            sum += bytes[from + len - 1].ord * 256
        end
        ~((sum >> 16) + sum) & 0xffff
    end

    # fom RFC 3022 4.2
    def self.checksum_adjust(sum, old_bytes, new_bytes)
        sum = ~sum & 0xffff;
        for i in 0 .. old_bytes.length / 2 - 1
            old = old_bytes[i * 2].ord * 256 + old_bytes[i * 2 + 1].ord;
            sum -= old;
            if sum <= 0
                sum -= 1
                sum &= 0xffff
            end
        end
        for i in 0 .. new_bytes.length / 2 - 1
            n = new_bytes[i * 2].ord * 256 + new_bytes[i * 2 + 1].ord;
            sum += n;
            if sum >= 0x10000
                sum += 1
                sum &= 0xffff
            end
        end
        ~sum & 0xffff
    end
end

class IPv4 < IP
    PROTOCOL_ID = 0x0800

    def _parse(packet)
        bytes = packet.bytes

        return nil if bytes.length < 20
        return nil if bytes[0].ord != 0x45
        # tos?
        # totlen?
        # ignore identification
        return nil if packet.decode_u16(6) & 0xbfff != 0 # ignore fragments
        @ttl = bytes[8].ord
        @proto = bytes[9].ord
        @checksum = packet.decode_u16(10)
        @src_addr = bytes[12..15]
        @dest_addr = bytes[16..19]

        packet.l4_start = 20
        self
    end

    def self.parse(packet)
        IPv4.new._parse(packet)
    end

    def tuple()
        @src_addr + @dest_addr
    end

    def _apply(packet)
        bytes = packet.bytes

        orig_tuple = bytes[12..19]

        @ttl -= 1
        bytes[8] = @ttl.chr

        bytes[12..15] = @src_addr
        bytes[16..19] = @dest_addr

        packet.encode_u16(10, 0)
        @checksum = IP.checksum(bytes, 0, packet.l4_start)
        packet.encode_u16(10, @checksum)

        orig_tuple
    end

end

class UDP
    PROTOCOL_ID = 17

    attr_reader :src_port, :dst_port, :checksum

    def _parse(packet)
        off = packet.l4_start

        return nil if packet.bytes.length - off < 8
        @src_port = packet.decode_u16(off)
        @dst_port = packet.decode_u16(off + 2)
        # length?
        @checksum = packet.decode_u16(off + 6)

        self
    end

    def self.parse(packet)
        UDP.new._parse(packet)
    end

    def _apply(packet, orig_l3_tuple)
        @checksum = IP.checksum_adjust(@checksum, orig_l3_tuple, packet.l3.tuple)
        packet.encode_u16(packet.l4_start + 6, @checksum)
    end
end

class TCP
    PROTOCOL_ID = 6

    attr_reader :src_port, :dst_port, :checksum, :flags

    def _parse(packet)
        off = packet.l4_start

        return nil if packet.bytes.length - off < 20
        @src_port = packet.decode_u16(off)
        @dst_port = packet.decode_u16(off + 2)
        # seq 4 bytes
        # ack 4 bytes
        @flags = packet.decode_u16(off + 12)
        # winsz 2 bytes
        @checksum = packet.decode_u16(off + 16)

        self
    end

    def self.parse(packet)
        TCP.new._parse(packet)
    end

    def _apply(packet, orig_l3_tuple)
        @checksum = IP.checksum_adjust(@checksum, orig_l3_tuple, packet.l3.tuple)
        packet.encode_u16(packet.l4_start + 16, @checksum)
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
        return Packet.new(bytes)
    end

    def write(packet)
        @tundev.syswrite(packet.bytes)
    end
end
