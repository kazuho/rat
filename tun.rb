# frozen_string_literal: true

require 'socket'

class IP
  ZERO_BYTES2 = "\0\0".b
  ZERO_BYTES4 = "\0\0\0\0".b
  ZERO_BYTES8 = "\0\0\0\0\0\0\0\0".b

  class V4
    def self.addr_size
      4
    end

    def self.l4_length(pseudo_header)
      pseudo_header[10..11].unpack1('n')
    end

    def self.set_l4_length(pseudo_header, packet_bytes, len)
      len = [len].pack('n')
      pseudo_header[10..11] = len
      packet_bytes[2..3] = len
    end

    def self.icmp_protocol_id
      ICMP::V4_PROTOCOL_ID
    end

    def self.l4_use_pseudo_header?
      false
    end

    def self.new_icmp(packet, type)
      case type
      when ICMPEcho::V4_TYPE_REQUEST
        ICMPEcho.new(packet, true)
      when ICMPEcho::V4_TYPE_REPLY
        ICMPEcho.new(packet, false)
      when ICMPError::V4_TYPE_DEST_UNREACH, ICMPError::V4_TYPE_TIME_EXCEEDED
        ICMPError.new(packet)
      else
        ICMP.new(packet)
      end
    end

    def self.parse(packet)
      bytes = packet.bytes

      return false if bytes.getbyte(0) != 0x45
      # tos?
      # totlen?
      # ignore identification
      return false if packet.decode_u16(6) & 0xbfff != 0 # ignore fragments

      packet.l4_start = 20

      proto = bytes.getbyte(9)
      packet.proto = proto

      # build pseudo header
      pseudo_header = bytes[12..19] + IP::ZERO_BYTES4
      pseudo_header.setbyte(9, proto)
      IP.encode_u16(pseudo_header, 10, bytes.length - 20)
      packet.pseudo_header = pseudo_header

      true
    end

    def self.apply(packet)
      bytes = packet.bytes

      # decrement TTL
      bytes.setbyte(8, bytes.getbyte(8) - 1)

      bytes[12..19] = packet.pseudo_header[0..7]

      bytes[10..11] = IP::ZERO_BYTES2
      checksum = IP.checksum(bytes, 0, packet.l4_start)
      packet.encode_u16(10, checksum)
    end
  end

  class V6
    EXTENSIONS = [0, 43, 44, 51, 50, 60, 135, 139, 140, 253, 254].map { |id| [id, true] }.to_h

    def self.addr_size
      16
    end

    def self.l4_length(pseudo_header)
      pseudo_header[34..35].unpack1('n')
    end

    def self.set_l4_length(pseudo_header, packet_bytes, len)
      len = [len].pack('n')
      pseudo_header[34..35] = len
      packet_bytes[4..5] = len
    end

    def self.icmp_protocol_id
      ICMP::V6_PROTOCOL_ID
    end

    def self.l4_use_pseudo_header?
      true
    end

    def self.new_icmp(packet, type)
      case type
      when ICMPEcho::V6_TYPE_REQUEST
        ICMPEcho.new(packet, true)
      when ICMPEcho::V6_TYPE_REPLY
        ICMPEcho.new(packet, false)
      when ICMPError::V6_TYPE_DEST_UNREACH, ICMPError::V6_TYPE_PACKET_TOO_BIG, ICMPError::V6_TYPE_TIME_EXCEEDED
        ICMPError.new(packet)
      else
        ICMP.new(packet)
      end
    end

    def self.parse(packet)
      bytes = packet.bytes

      return false if bytes.length < 40

      proto = bytes.getbyte(6)

      # drop packets containing IPv6 extensions (RFC 7045 grudgingly acknowledges existence of such middleboxes)
      return false if EXTENSIONS[proto]

      packet.proto = proto
      packet.l4_start = 40

      # build pseudo header
      pseudo_header = bytes[8..39] + IP::ZERO_BYTES8
      IP.encode_u16(pseudo_header, 34, bytes.length - 40)
      pseudo_header.setbyte(39, proto)
      packet.pseudo_header = pseudo_header

      true
    end

    def self.apply(packet)
      bytes = packet.bytes

      # decrement hop limit
      bytes.setbyte(7, bytes.getbyte(7) - 1)

      bytes[8..39] = packet.pseudo_header[0..31]
    end
  end

  attr_accessor :bytes, :proto, :l4_start, :l4, :pseudo_header, :orig_pseudo_header
  attr_reader :version

  def initialize(bytes)
    @bytes = bytes
  end

  def _parse(icmp_payload)
    bytes = @bytes

    # mimimum size for IPv4
    return nil if bytes.length < 20

    case bytes.getbyte(0) >> 4
    when 4
      @version = V4
    when 6
      @version = V6
    else
      return nil
    end

    return nil unless @version.parse(self)

    @orig_pseudo_header = @pseudo_header.dup

    case @proto
    when UDP::PROTOCOL_ID
      self.l4 = UDP.parse(self, icmp_payload)
    when TCP::PROTOCOL_ID
      self.l4 = TCP.parse(self, icmp_payload)
    when @version.icmp_protocol_id
      self.l4 = ICMP.parse(self)
    end

    self
  end

  def self.parse(bytes, icmp_payload = false)
    IP.new(bytes)._parse(icmp_payload)
  end

  def src_addr
    addr_size = @version.addr_size
    @pseudo_header.byteslice(0, addr_size)
  end

  def src_addr=(x)
    addr_size = @version.addr_size
    @pseudo_header.bytesplice(0, addr_size, x)
  end

  def dest_addr
    addr_size = @version.addr_size
    @pseudo_header.byteslice(addr_size, addr_size)
  end

  def dest_addr=(x)
    addr_size = @version.addr_size
    @pseudo_header.bytesplice(addr_size, addr_size, x)
  end

  def tuple
    addr_size = @version.addr_size
    @pseudo_header.byteslice(0, addr_size * 2)
  end

  def l4_length
    @version.l4_length(@pseudo_header)
  end

  def l4_length=(x)
    @version.set_l4_length(@pseudo_header, @bytes, x)
  end

  def apply
    @version.apply(self)
    l4.apply
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
    case addr.length
    when 4
      addr.unpack('C4').join('.')
    when 16
      addr.unpack('n8').map { |f| format '%x', f }.join(':').gsub!(/(:0)+(?=:)/, ':')
    else
      raise 'unexpected address length of %{addr.length}'
    end
  end
end

class TCPUDP
  def initialize(packet)
    @packet = packet
    @orig_tuple = packet.bytes.byteslice(packet.l4_start, 4)
  end

  def src_port
    @packet.decode_u16(@packet.l4_start)
  end

  def src_port=(n)
    @packet.encode_u16(@packet.l4_start, n)
  end

  def dest_port
    @packet.decode_u16(@packet.l4_start + 2)
  end

  def dest_port=(n)
    @packet.encode_u16(@packet.l4_start + 2, n)
  end

  def tuple
    @packet.bytes.byteslice(@packet.l4_start, 4)
  end

  def _apply(checksum_offset)
    packet = @packet
    bytes = packet.bytes
    l4_start = packet.l4_start

    orig_bytes = packet.orig_pseudo_header + @orig_tuple
    new_bytes = packet.pseudo_header + bytes.byteslice(l4_start, 4)

    return unless bytes.length >= l4_start + checksum_offset + 2

    checksum = packet.decode_u16(l4_start + checksum_offset)
    checksum = IP.checksum_adjust(checksum, orig_bytes, new_bytes)
    packet.encode_u16(l4_start + checksum_offset, checksum)
  end
end

class UDP < TCPUDP
  PROTOCOL_ID = 17
  CHECKSUM_OFFSET = 6

  def self.parse(packet, icmp_payload)
    return nil if packet.bytes.length < packet.l4_start + (icmp_payload ? 4 : 8)

    UDP.new(packet)
  end

  def apply
    _apply(CHECKSUM_OFFSET)
  end
end

class TCP < TCPUDP
  PROTOCOL_ID = 6
  DATA_OFFSET_OFFSET = 12
  CHECKSUM_OFFSET = 16
  OPTION_KIND_END = 0
  OPTION_KIND_NOOP = 1
  OPTION_KIND_MSS = 2
  FLAG_FIN = 0x01
  FLAG_SYN = 0x02
  FLAG_RST = 0x04
  FLAG_PST = 0x08
  FLAG_ACK = 0x10
  FLAG_URG = 0x20
  FLAG_ECE = 0x40
  FLAG_CWR = 0x80

  attr_reader :flags

  def initialize(packet, flags)
    super(packet)
    @flags = flags
  end

  def self.parse(packet, icmp_payload)
    bytes = packet.bytes
    l4_start = packet.l4_start
    return nil if bytes.length < l4_start + (icmp_payload ? 4 : 20)

    flags = bytes.getbyte(l4_start + 13)
    TCP.new(packet, flags)
  end

  def max_segment_size
    mss = nil
    each_option do |kind, value|
      if kind == 2 && value.length == 2
        mss = value.unpack1('n') if kind == 2 && value.length == 2
        break
      end
    end
    mss
  end

  def max_segment_size=(newval)
    oldoff = _calc_l7_start
    oldlen = 0
    each_option do |kind, value, off|
      next unless kind == OPTION_KIND_MSS && value.length == 2

      oldoff = off
      oldlen = 4
      break
    end
    if newval
      _splice_option(oldoff, oldlen, OPTION_KIND_MSS, [newval].pack('n'))
    else
      _splice_option(oldoff, oldlen, nil, nil)
    end

    newval
  end

  def apply
    _apply(16)
  end

  def each_option
    bytes = @packet.bytes

    off = @packet.l4_start + 20
    l7_start = _calc_l7_start || 0
    while off < l7_start
      optkind = bytes.getbyte(off)
      case optkind
      when OPTION_KIND_END
        break
      when OPTION_KIND_NOOP
        off += 1
      else
        # other TCP Options are TLV
        optlen = bytes.getbyte(off + 1)
        break if optlen < 2
        break if off + optlen > l7_start

        optval = bytes.byteslice(off + 2, optlen - 2)
        yield optkind, optval, off
        off += optlen
      end
    end
  end

  def _splice_option(off, len, optkind, optval)
    bytes = @packet.bytes
    l4_start = @packet.l4_start
    l7_start = _calc_l7_start
    return false unless l7_start

    replace = if optkind
                optkind.chr + (optval.length + 2).chr + optval
              else
                ''
              end

    # rewrite Option, retaining the bytes for checksum calculation
    orig_checksum_bytes = bytes.byteslice(off, len)
    new_checksum_bytes = replace
    bytes.bytesplice(off, len, replace)

    # make necessary adjustments if TCP header size and hence the packet size have changed
    if len != replace.length
      @packet.l4_length += replace.length - len
      new_data_offset = (l7_start - l4_start) + (replace.length - len)
      raise 'have to adjust padding but that is not implemented yet' if new_data_offset % 4 != 0

      orig_checksum_bytes += bytes.byteslice(l4_start + DATA_OFFSET_OFFSET, 2)
      bytes.setbyte(l4_start + DATA_OFFSET_OFFSET,
                    (new_data_offset / 4) << 4 | (bytes.getbyte(l4_start + DATA_OFFSET_OFFSET) & 0xf))
      new_checksum_bytes += bytes.byteslice(l4_start + DATA_OFFSET_OFFSET, 2)
    end

    checksum = bytes.byteslice(l4_start + CHECKSUM_OFFSET, 2).unpack1('n')
    checksum = IP.checksum_adjust(checksum, orig_checksum_bytes, new_checksum_bytes)
    IP.encode_u16(bytes, l4_start + CHECKSUM_OFFSET, checksum)

    true
  end

  def _calc_l7_start
    bytes = @packet.bytes
    l4_start = @packet.l4_start
    return nil if bytes.length < l4_start + 20

    l7_start = l4_start + (bytes.getbyte(l4_start + DATA_OFFSET_OFFSET) >> 4) * 4
    return nil if bytes.length < l7_start

    l7_start
  end
end

class ICMP
  V4_PROTOCOL_ID = 1
  V6_PROTOCOL_ID = 58

  attr_reader :type, :code

  def initialize(packet)
    @packet = packet
  end

  def _parse
    bytes = @packet.bytes
    off = @packet.l4_start

    @type = bytes.getbyte(off)
    @code = bytes.getbyte(off + 1)

    self
  end

  def self.parse(packet)
    bytes = packet.bytes
    off = packet.l4_start

    return nil if bytes.length - off < 8

    type = bytes.getbyte(off)
    icmp = packet.version.new_icmp(packet, type)
    icmp._parse
  end

  def apply
    # ICMP does not use pseudo headers
  end

  def self.recalculate_checksum(packet)
    packet.encode_u16(packet.l4_start + 2, 0)
    checksum = IP.checksum(packet.bytes, packet.l4_start)
    checksum = IP.checksum_adjust(checksum, '', packet.pseudo_header) if packet.version.l4_use_pseudo_header?
    packet.encode_u16(packet.l4_start + 2, checksum)
  end
end

class ICMPEcho < ICMP
  V4_TYPE_REQUEST = 8
  V4_TYPE_REPLY = 0
  V6_TYPE_REQUEST = 128
  V6_TYPE_REPLY = 129

  attr_accessor :src_port, :dest_port

  def initialize(packet, is_req)
    super(packet)
    @is_req = is_req
  end

  def _parse
    super

    port = @packet.decode_u16(@packet.l4_start + 4)
    if @is_req
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

  def apply
    @packet.encode_u16(@packet.l4_start + 4, @is_req ? @src_port : @dest_port)
    ICMP.recalculate_checksum(@packet)
  end
end

class ICMPError < ICMP
  V4_TYPE_DEST_UNREACH = 3
  V4_TYPE_TIME_EXCEEDED = 11
  V6_TYPE_DEST_UNREACH = 1
  V6_TYPE_PACKET_TOO_BIG = 2
  V6_TYPE_TIME_EXCEEDED = 3

  attr_accessor :original

  def _parse
    super

    @original = IP.parse(@packet.bytes[@packet.l4_start + 8..], true)
    return nil if @original.nil? || @original.version != @packet.version || @original.l4.nil?

    self
  end

  def apply
    @original.apply

    # overwrite packet image with orig packet being built
    @packet.bytes[@packet.l4_start + 8..] = @original.bytes

    ICMP.recalculate_checksum(@packet)
  end
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
