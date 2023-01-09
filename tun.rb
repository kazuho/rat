# frozen_string_literal: true

require 'socket'

class IP
  ZERO_SIZED_BUFFER = IO::Buffer.new(0)

  class V4
    def self.addr_size
      4
    end

    def self.l4_length(pseudo_header)
      pseudo_header.get_value(:U16, 10)
    end

    def self.set_l4_length(pseudo_header, packet_bytes, len)
      pseudo_header.set_value(:U16, 10, len)
      packet_bytes.set_value(:U16, 2, len)
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

      return false if bytes.get_value(:U8, 0) != 0x45
      # tos?
      # totlen?
      # ignore identification
      return false if bytes.get_value(:U16, 6) & 0xbfff != 0 # ignore fragments

      packet.l4_start = 20

      proto = bytes.get_value(:U8, 9)
      packet.proto = proto

      # build pseudo header
      pseudo_header = IO::Buffer.new(12)
      pseudo_header.copy(bytes, 0, 8, 12)
      pseudo_header.set_value(:U8, 9, proto)
      pseudo_header.set_value(:U16, 10, bytes.size - 20)
      packet.pseudo_header = pseudo_header

      true
    end

    def self.apply(packet)
      bytes = packet.bytes

      # decrement TTL
      bytes.set_value(:U8, 8, bytes.get_value(:U8, 8) - 1)

      bytes.copy(packet.pseudo_header, 12, 8)

      bytes.set_value(:U16, 10, 0)
      checksum = IP.checksum(bytes, 0, packet.l4_start)
      bytes.set_value(:U16, 10, checksum)
    end
  end

  class V6
    EXTENSIONS = [0, 43, 44, 51, 50, 60, 135, 139, 140, 253, 254].map { |id| [id, true] }.to_h

    def self.addr_size
      16
    end

    def self.l4_length(pseudo_header)
      pseudo_header.get_value(:U16, 34)
    end

    def self.set_l4_length(pseudo_header, packet_bytes, len)
      pseudo_header.set_value(:U16, 34, len)
      packet_bytes.set_value(:U16, 4, len)
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

      return false if bytes.size < 40

      proto = bytes.get_value(:U8, 6)

      # drop packets containing IPv6 extensions (RFC 7045 grudgingly acknowledges existence of such middleboxes)
      return false if EXTENSIONS[proto]

      packet.proto = proto
      packet.l4_start = 40

      # build pseudo header
      pseudo_header = IO::Buffer.new(40)
      pseudo_header.copy(bytes, 0, 32, 8)
      pseudo_header.set_value(:U32, 32, bytes.size - 40)
      pseudo_header.set_value(:U8, 39, proto)
      packet.pseudo_header = pseudo_header

      true
    end

    def self.apply(packet)
      bytes = packet.bytes

      # decrement hop limit
      bytes.set_value(:U8, 7, bytes.get_value(:U8, 7) - 1)

      bytes.copy(packet.pseudo_header, 8, 32)
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
    return nil if bytes.size < 20

    case bytes.get_value(:U8, 0) >> 4
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
    @pseudo_header.slice(0, addr_size)
  end

  def src_addr=(x)
    addr_size = @version.addr_size
    @pseudo_header.copy(x, 0)
  end

  def dest_addr
    addr_size = @version.addr_size
    @pseudo_header.slice(addr_size, addr_size)
  end

  def dest_addr=(x)
    addr_size = @version.addr_size
    @pseudo_header.copy(x, addr_size)
  end

  def tuple
    addr_size = @version.addr_size
    @pseudo_header.slice(0, addr_size * 2)
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

  def self.checksum(bytes, from = nil, len = nil)
    from = 0 if from.nil?
    len = bytes.size - from if len.nil?

    sum = 0
    to = from + len / 2 * 2
    while from < to
      sum += bytes.get_value(:U16, from)
      from += 2
    end
    sum += bytes.get_value(:U8, from) * 256 if len.odd?

    while sum > 65535
      sum = (sum & 0xffff) + (sum >> 16)
    end

    ~sum & 0xffff
  end

  # fom RFC 3022 4.2
  def self.checksum_adjust(sum, old_bytes, new_bytes)
    sum = ~sum & 0xffff

    off = 0
    len = old_bytes.size
    while off < len
      sum -= old_bytes.get_value(:U16, off)
      off += 2
    end
    while sum < 0
      sum = (sum & 0xffff) + (sum >> 16)
    end

    off = 0
    len = new_bytes.size
    while off < len
      sum += new_bytes.get_value(:U16, off)
      off += 2
    end
    while sum > 65535
      sum = (sum & 0xffff) + (sum >> 16)
    end

    ~sum & 0xffff
  end

  def self.addr_to_s(addr)
    case addr.size
    when 4
      (0 .. 3).flat_map { |i| addr.get_value(:U8, i).to_s }.join('.')
    when 16
      (0 .. 7).flat_map { |i| format '%x', addr.get_value(:U16, i * 2) }.join(':').gsub!(/(:0)+(?=:)/, ':')
    else
      raise 'unexpected address length of %{addr.length}'
    end
  end
end

class TCPUDP
  def initialize(packet)
    @packet = packet
    @orig_tuple = packet.bytes.slice(packet.l4_start, 4).dup
  end

  def src_port
    @packet.bytes.get_value(:U16, @packet.l4_start)
  end

  def src_port=(n)
    @packet.bytes.set_value(:U16, @packet.l4_start, n)
  end

  def dest_port
    @packet.bytes.get_value(:U16, @packet.l4_start + 2)
  end

  def dest_port=(n)
    @packet.bytes.set_value(:U16, @packet.l4_start + 2, n)
  end

  def tuple
    @packet.bytes.slice(@packet.l4_start, 4).dup
  end

  def _apply(checksum_offset)
    packet = @packet
    bytes = packet.bytes
    l4_start = packet.l4_start

    return unless bytes.size >= l4_start + checksum_offset + 2

    checksum = bytes.get_value(:U16, l4_start + checksum_offset)
    checksum = IP.checksum_adjust(checksum, packet.orig_pseudo_header, packet.pseudo_header)
    checksum = IP.checksum_adjust(checksum, @orig_tuple, bytes.slice(l4_start, 4))
    bytes.set_value(:U16, l4_start + checksum_offset, checksum)
  end
end

class UDP < TCPUDP
  PROTOCOL_ID = 17
  CHECKSUM_OFFSET = 6

  def self.parse(packet, icmp_payload)
    return nil if packet.bytes.size < packet.l4_start + (icmp_payload ? 4 : 8)

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
    return nil if bytes.size < l4_start + (icmp_payload ? 4 : 20)

    flags = bytes.get_value(:U8, l4_start + 13)
    TCP.new(packet, flags)
  end

  def max_segment_size
    mss = nil
    each_option do |kind, value|
      if kind == 2 && value.size == 2
        mss = value.get_value(:U16, 0)
        break
      end
    end
    mss
  end

  def max_segment_size=(newval)
    oldoff = _calc_l7_start
    oldlen = 0
    each_option do |kind, value, off|
      next unless kind == OPTION_KIND_MSS && value.size == 2

      oldoff = off
      oldlen = 4
      break
    end
    if newval
      newval_bytes = IO::Buffer.new(4)
      newval_bytes.set_value(:U8, 0, OPTION_KIND_MSS)
      newval_bytes.set_value(:U8, 1, 4)
      newval_bytes.set_value(:U16, 2, newval)
      _splice_option(oldoff, oldlen, newval_bytes)
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
      optkind = bytes.get_value(:U8, off)
      case optkind
      when OPTION_KIND_END
        break
      when OPTION_KIND_NOOP
        off += 1
      else
        # other TCP Options are TLV
        optlen = bytes.get_value(:U8, off + 1)
        break if optlen < 2
        break if off + optlen > l7_start

        optval = bytes.slice(off + 2, optlen - 2)
        yield optkind, optval, off
        off += optlen
      end
    end
  end

  def _splice_option(off, len, replace)
    bytes = @packet.bytes
    l4_start = @packet.l4_start
    l7_start = _calc_l7_start
    return false unless l7_start

    checksum = bytes.get_value(:U16, l4_start + CHECKSUM_OFFSET)

    # rewrite Option
    IP.checksum_adjust(checksum, bytes.slice(off, len), replace)
    if len != replace.size
      bytes.resize(replace.size - len)
      bytes.copy(bytes, off + replace.size, bytes.size - (off + replace.size), off + len)
    end
    bytes.copy(replace, off, replace.len)

    # make necessary adjustments if TCP header size and hence the packet size have changed
    if len != replace.size
      @packet.l4_length += replace.length - len
      new_data_offset = (l7_start - l4_start) + (replace.length - len)
      raise 'have to adjust padding but that is not implemented yet' if new_data_offset % 4 != 0

      orig_twobytes = bytes.slice(l4_start + DATA_OFFSET_OFFSET, 2).dup
      bytes.set_value(:U8, l4_start + DATA_OFFSET_OFFSET,
                    (new_data_offset / 4) << 4 | (bytes.get_value(:U8, l4_start + DATA_OFFSET_OFFSET) & 0xf))
      IP.checksum_adjust(checksum, orig_twobytes, bytes.slice(l4_start + DATA_OFFSET_OFFSET, 2))
    end

    bytes.set_value(:U16, l4_start + CHECKSUM_OFFSET, checksum)

    true
  end

  def _calc_l7_start
    bytes = @packet.bytes
    l4_start = @packet.l4_start
    return nil if bytes.size < l4_start + 20

    l7_start = l4_start + (bytes.get_value(:U8, l4_start + DATA_OFFSET_OFFSET) >> 4) * 4
    return nil if bytes.size < l7_start

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

    @type = bytes.get_value(:U8, off)
    @code = bytes.get_value(:U8, off + 1)

    self
  end

  def self.parse(packet)
    bytes = packet.bytes
    off = packet.l4_start

    return nil if bytes.size - off < 8

    type = bytes.get_value(:U8, off)
    icmp = packet.version.new_icmp(packet, type)
    icmp._parse
  end

  def apply
    # ICMP does not use pseudo headers
  end

  def self.recalculate_checksum(packet)
    bytes = packet.bytes
    l4_start = packet.l4_start

    bytes.set_value(:U16, l4_start + 2, 0)
    checksum = IP.checksum(bytes, l4_start)
    checksum = IP.checksum_adjust(checksum, ZERO_SIZED_BUFFER, packet.pseudo_header) if packet.version.l4_use_pseudo_header?
    bytes.set_value(:U16, l4_start + 2, checksum)
  end
end

class ICMPEcho < ICMP
  V4_TYPE_REQUEST = 8
  V4_TYPE_REPLY = 0
  V6_TYPE_REQUEST = 128
  V6_TYPE_REPLY = 129

  attr_accessor :tuple

  def initialize(packet, is_req)
    super(packet)
    @is_req = is_req
  end

  def _parse
    super

    @tuple = IO::Buffer.new(4)
    @tuple.copy(@packet.bytes, @is_req ? 0 : 2, 2, @packet.l4_start + 4)

    self
  end

  def src_port
    @tuple.get_value(:U16, 0)
  end

  def src_port=(x)
    @tuple.set_value(:U16, 0, x)
  end

  def dest_port
    @tuple.get_value(:U16, 2)
  end

  def dest_port=(x)
    @tuple.set_value(:U16, 2, x)
  end

  def apply
    @packet.bytes.copy(@tuple, @packet.l4_start + 4, 2, @is_req ? 0 : 2)
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

    original_off = @packet.l4_start + 8
    @original = IP.parse(@packet.bytes.slice(original_off, @packet.bytes.size - original_off).dup, true)
    return nil if @original.nil? || @original.version != @packet.version || @original.l4.nil?

    self
  end

  def apply
    @original.apply

    # overwrite packet image with orig packet being built
    original_off = @packet.l4_start + 8
    @packet.bytes.resize(original_off + @original.bytes.size)
    @packet.bytes.copy(@original.bytes, original_off)

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
    bytes = IO::Buffer.new(1500)
    size = bytes.read(@tundev, bytes.size)
    bytes.resize(size)
    IP.parse(bytes)
  end

  def write(packet)
    packet.apply
    bytes = packet.bytes
    bytes.write(@tundev, bytes.size)
  end
end
