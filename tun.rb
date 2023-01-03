# frozen_string_literal: true

require 'socket'

class IP
  attr_accessor :bytes, :l4_start, :l4, :pseudo_header, :orig_pseudo_header

  def initialize(bytes)
    @bytes = bytes
  end

  def _parse(allow_partial)
    bytes = @bytes

    return nil if bytes.length < 20
    return nil if bytes.getbyte(0) != 0x45
    # tos?
    # totlen?
    # ignore identification
    return nil if decode_u16(6) & 0xbfff != 0 # ignore fragments

    @l4_start = 20

    proto = bytes.getbyte(9)

    # build pseudo header and retain it
    pseudo_header = bytes[12..19] + "\0\0\0\0".b
    pseudo_header.setbyte(9, proto)
    IP.encode_u16(pseudo_header, 10, bytes.length - 20)
    @pseudo_header = pseudo_header
    @orig_pseudo_header = pseudo_header.dup

    case proto
    when UDP::PROTOCOL_ID
      self.l4 = UDP.parse(self, allow_partial)
    when TCP::PROTOCOL_ID
      self.l4 = TCP.parse(self, allow_partial)
    when ICMP::PROTOCOL_ID
      self.l4 = ICMP.parse(self)
    end

    self
  end

  def self.parse(bytes, allow_partial = false)
    IP.new(bytes)._parse(allow_partial)
  end

  def src_addr
    @pseudo_header[0..3]
  end

  def src_addr=(x)
    @pseudo_header[0..3] = x
  end

  def dest_addr
    @pseudo_header[4..7]
  end

  def dest_addr=(x)
    @pseudo_header[4..7] = x
  end

  def tuple
    @pseudo_header[0..7]
  end

  def apply
    bytes = @bytes

    # decrement TTL
    bytes.setbyte(8, bytes.getbyte(8) - 1)

    bytes[12..19] = @pseudo_header[0..7]

    bytes[10..11] = "\0\0"
    checksum = IP.checksum(bytes, 0, l4_start)
    encode_u16(10, checksum)

    l4.apply(self)
  end

  def decode_u16(off)
    @bytes[off..off + 1].unpack1('n')
  end

  def encode_u16(off, v)
    IP.encode_u16(@bytes, off, v)
  end

  def self.encode_u16(bytes, off, v)
    # this seems faster than pack-then-replace
    bytes.setbyte(off, (v >> 8) & 0xff)
    bytes.setbyte(off + 1, v & 0xff)
  end

  def self.checksum(bytes, from = nil, len = nil)
    from = 0 if from.nil?
    len = bytes.length - from if len.nil?
    to = from + len - 1

    sum = bytes[from..to].unpack('n*').sum
    sum += bytes.getbyte(to) * 256 if len.odd?
    ~((sum >> 16) + sum) & 0xffff
  end

  # fom RFC 3022 4.2
  def self.checksum_adjust(sum, old_bytes, new_bytes)
    sum = ~sum & 0xffff
    old_bytes.unpack('n*').each do |u16|
      sum -= u16
      if sum <= 0
        sum -= 1
        sum &= 0xffff
      end
    end
    new_bytes.unpack('n*').each do |u16|
      sum += u16
      if sum >= 0x10000
        sum += 1
        sum &= 0xffff
      end
    end
    ~sum & 0xffff
  end

  def self.addr_to_s(addr)
    addr.unpack('C4').join('.')
  end
end

class TCPUDP
  attr_accessor :tuple

  def src_port
    @tuple[0..1].unpack1('n')
  end

  def src_port=(n)
    IP.encode_u16(@tuple, 0, n)
  end

  def dest_port
    @tuple[2..3].unpack1('n')
  end

  def dest_port=(n)
    IP.encode_u16(@tuple, 2, n)
  end

  def _parse(packet, min_len)
    bytes = packet.bytes
    off = packet.l4_start

    return nil if bytes.length - off < min_len

    @tuple = packet.bytes[off..off + 3]

    self
  end

  def _apply(packet, checksum_offset)
    bytes = packet.bytes
    l4_start = packet.l4_start

    orig_bytes = packet.orig_pseudo_header + bytes[l4_start..l4_start + 3]
    bytes[l4_start..l4_start + 3] = @tuple
    new_bytes = packet.pseudo_header + @tuple

    return unless bytes.length >= l4_start + checksum_offset + 2

    checksum = packet.decode_u16(l4_start + checksum_offset)
    checksum = IP.checksum_adjust(checksum, orig_bytes, new_bytes)
    packet.encode_u16(l4_start + checksum_offset, checksum)
  end
end

class UDP < TCPUDP
  PROTOCOL_ID = 17

  def self.parse(packet, allow_partial)
    UDP.new._parse(packet, allow_partial ? 4 : 8)
  end

  def apply(packet)
    _apply(packet, 6)
  end
end

class TCP < TCPUDP
  PROTOCOL_ID = 6

  def self.parse(packet, allow_partial)
    TCP.new._parse(packet, allow_partial ? 4 : 20)
  end

  def apply(packet)
    _apply(packet, 16)
  end
end

class ICMP
  PROTOCOL_ID = 1

  attr_reader :type, :code, :checksum

  def _parse(packet)
    bytes = packet.bytes
    off = packet.l4_start

    @type = bytes.getbyte(off)
    @code = bytes.getbyte(off + 1)
    @checksum = packet.decode_u16(off + 2)

    self
  end

  def self.parse(packet)
    bytes = packet.bytes
    off = packet.l4_start

    return nil if bytes.length - off < 8

    type = bytes.getbyte(off)
    icmp = if [ICMPEcho::TYPE_ECHO, ICMPEcho::TYPE_REPLY].include?(type)
             ICMPEcho.new
           elsif type == ICMPDestUnreach::TYPE
             ICMPDestUnreach.new
           elsif type == ICMPTimeExceeded::TYPE
             ICMPTimeExceeded.new
           else
             ICMP.new
           end

    icmp._parse(packet)
  end

  def apply(packet)
    # ICMP does not use pseudo headers
  end

  def self.recalculate_checksum(packet)
    packet.encode_u16(packet.l4_start + 2, 0)
    @checksum = IP.checksum(packet.bytes, packet.l4_start)
    packet.encode_u16(packet.l4_start + 2, @checksum)
  end
end

class ICMPEcho < ICMP
  TYPE_REPLY = 0
  TYPE_ECHO = 8

  attr_accessor :src_port, :dest_port

  def _parse(packet)
    return nil if super(packet).nil?

    port = packet.decode_u16(packet.l4_start + 4)
    if type == TYPE_ECHO
      @src_port = port
      @dest_port = 0
    else
      @src_port = 0
      @dest_port = port
    end
    self
  end

  def tuple
    [src_port, dest_port].pack('n*')
  end

  def apply(packet)
    packet.encode_u16(packet.l4_start + 4, type == TYPE_ECHO ? @src_port : @dest_port)
    ICMP.recalculate_checksum(packet)
  end
end

class ICMPWithOriginalPacket < ICMP
  attr_accessor :original

  def _parse(packet)
    return nil if super(packet).nil?

    @original = IP.parse(packet.bytes[packet.l4_start + 8..], true)
    return nil if @original.nil? || @original.l4.nil?

    self
  end

  def apply(packet)
    @original.apply

    # overwrite packet image with orig packet being built
    packet.bytes[packet.l4_start + 8..] = @original.bytes

    ICMP.recalculate_checksum(packet)
  end
end

class ICMPDestUnreach < ICMPWithOriginalPacket
  TYPE = 3
end

class ICMPTimeExceeded < ICMPWithOriginalPacket
  TYPE = 11
end

class Tun
  IFF_TUN = 1
  IFF_NO_PI = 0x1000
  TUNSETIFF = 0x400454ca

  def initialize(devname)
    @tundev = open('/dev/net/tun', 'r+')

    ifreq = [devname, IFF_TUN | IFF_NO_PI].pack("a#{Socket::IFNAMSIZ}s!")
    @tundev.ioctl(TUNSETIFF, ifreq)
  end

  def read
    bytes = @tundev.readpartial(1500)
    IP.parse(bytes)
  end

  def write(packet)
    @tundev.syswrite(packet.bytes)
  end
end
