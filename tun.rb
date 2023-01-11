# frozen_string_literal: true

require 'socket'

class String
  def get16be(off)
    getbyte(off) * 256 + getbyte(off + 1)
  end

  def set16be(off, v)
    # this seems faster than pack-then-replace
    setbyte(off, (v >> 8) & 0xff)
    setbyte(off + 1, v & 0xff)
  end
end

class IP
  ZERO_BYTES2 = "\0\0".b

  class V4
    def self.src_addr(bytes)
      bytes.byteslice(12, 4)
    end

    def self.set_src_addr(bytes, new_addr)
      cs_delta = new_addr.unpack('n*').sum - bytes.unpack('@12n2').sum
      bytes.bytesplice(12, 4, new_addr)
      cs_delta
    end

    def self.dest_addr(bytes)
      bytes.byteslice(16, 4)
    end

    def self.set_dest_addr(bytes, new_addr)
      cs_delta = new_addr.unpack('n*').sum - bytes.unpack('@16n2').sum
      bytes.bytesplice(16, 4, new_addr)
      cs_delta
    end

    def self.tuple(bytes)
      bytes.byteslice(12, 8)
    end

    def self.l4_length(pseudo_header)
      pseudo_header.get16be(10)
    end

    def self.set_l4_length(pseudo_header, packet_bytes, len)
      pseudo_header.set16be(10, len)
      packet_bytes.set16be(2, len)
    end

    def self.icmp_protocol_id
      ICMP::V4_PROTOCOL_ID
    end

    def self.icmp_cs_delta(packet)
      0
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
      return false if bytes.get16be(6) & 0xbfff != 0 # ignore fragments

      packet.l4_start = 20

      proto = bytes.getbyte(9)
      packet.proto = proto

      true
    end

    def self.apply(packet)
      bytes = packet.bytes

      # decrement TTL
      bytes.setbyte(8, bytes.getbyte(8) - 1)

      bytes.bytesplice(10, 2, IP::ZERO_BYTES2)
      checksum = IP.checksum(bytes, 0, packet.l4_start)
      bytes.set16be(10, checksum)
    end
  end

  class V6
    EXTENSIONS = [0, 43, 44, 51, 50, 60, 135, 139, 140, 253, 254].map { |id| [id, true] }.to_h

    def self.src_addr(bytes)
      bytes.byteslice(8, 16)
    end

    def self.set_src_addr(bytes, new_addr)
      cs_delta = new_addr.unpack('n*').sum - bytes.unpack('@8n8').sum
      bytes.bytesplice(8, 16, new_addr)
      cs_delta
    end

    def self.get_dest_addr(bytes)
      bytes.byteslice(24, 16)
    end

    def self.set_dest_addr(bytes, new_addr)
      cs_delta = new_addr.unpack('n*').sum - bytes.unpack('@24n8').sum
      bytes.bytesplice(24, 16, new_addr)
      cs_delta
    end

    def self.tuple(bytes)
      bytes.byteslice(8, 32)
    end

    def self.l4_length(pseudo_header)
      pseudo_header.get16be(34)
    end

    def self.set_l4_length(pseudo_header, packet_bytes, len)
      pseudo_header.set16be(34, len)
      packet_bytes.set16be(4, len)
    end

    def self.icmp_protocol_id
      ICMP::V6_PROTOCOL_ID
    end

    def self.icmp_cs_delta(packet)
      upper_layer_packet_length = packet.bytes.length - packet.l4_start
      (packet.tuple + upper_layer_packet_length + packet.proto).unpack('n*').sum
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

      true
    end

    def self.apply(packet)
      bytes = packet.bytes

      # decrement hop limit
      bytes.setbyte(7, bytes.getbyte(7) - 1)
    end
  end

  attr_accessor :bytes, :proto, :l4_start, :l4
  attr_reader :version

  def initialize(bytes)
    @bytes = bytes
    @l7_cs_delta = 0
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

  def self.parse(bytes, icmp_payload: false)
    IP.new(bytes)._parse(icmp_payload)
  end

  def src_addr
    @version.src_addr(@bytes)
  end

  def src_addr=(new_addr)
    @l7_cs_delta += @version.set_src_addr(@bytes, new_addr)
  end

  def dest_addr
    @version.dest_addr(@bytes)
  end

  def dest_addr=(new_addr)
    @l7_cs_delta += @version.set_dest_addr(@bytes, new_addr)
  end

  def tuple
    @version.tuple(@bytes)
  end

  def l4_length
    @bytes.length - l4_start
  end

  def l4_length=(new_length)
    orig_length = @bytes.length - l4_start
    @version.set_l4_length(@bytes, new_length)
    @l7_cs_delta += new_length - orig_length
  end

  def apply
    @version.apply(self)
    l4.apply(@l7_cs_delta)
  end

  def self.checksum(bytes, from = nil, len = nil)
    from = 0 if from.nil?
    len = bytes.length - from if len.nil?
    to = from + len - 1

    sum = bytes[from..to].unpack('n*').sum
    sum += bytes.getbyte(to) * 256 if len.odd?
    sum = (sum & 0xffff) + (sum >> 16) while sum > 65535
    ~sum & 0xffff
  end

  # fom RFC 3022 4.2
  def self.checksum_adjust(sum, delta)
    sum = ~sum & 0xffff
    sum += delta
    sum = (sum & 0xffff) + (sum >> 16) while sum < 0 || sum > 65535
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
  attr_reader :src_port, :dest_port

  def initialize(packet)
    bytes = packet.bytes
    l4_start = packet.l4_start

    @packet = packet
    @src_port = bytes.get16be(l4_start)
    @dest_port = bytes.get16be(l4_start + 2)
    @orig_checksum = @src_port + @dest_port
  end

  def src_port=(n)
    @src_port = n
    @packet.bytes.set16be(@packet.l4_start, n)
  end

  def dest_port=(n)
    @dest_port = n
    @packet.bytes.set16be(@packet.l4_start + 2, n)
  end

  def tuple
    @packet.bytes.byteslice(@packet.l4_start, 4)
  end

  def _apply(checksum_offset, cs_delta)
    packet = @packet
    bytes = packet.bytes
    l4_start = packet.l4_start

    return unless bytes.length >= l4_start + checksum_offset + 2

    cs_delta += @src_port + @dest_port - @orig_checksum
    checksum = bytes.get16be(l4_start + checksum_offset)
    checksum = IP.checksum_adjust(checksum, cs_delta)
    bytes.set16be(l4_start + checksum_offset, checksum)
  end
end

class UDP < TCPUDP
  PROTOCOL_ID = 17
  CHECKSUM_OFFSET = 6

  def self.parse(packet, icmp_payload)
    return nil if packet.bytes.length < packet.l4_start + (icmp_payload ? 4 : 8)

    UDP.new(packet)
  end

  def apply(cs_delta)
    _apply(CHECKSUM_OFFSET, cs_delta)
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

  def apply(cs_delta)
    _apply(16, cs_delta)
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

    # rewrite Option, retaining checksum delta
    cs_delta = replace.unpack('n*').sum - bytes.byteslice(off, len).unpack('n*').sum
    bytes.bytesplice(off, len, replace)

    # make necessary adjustments if TCP header size and hence the packet size have changed
    if len != replace.length
      @packet.l4_length += replace.length - len
      new_data_offset = (l7_start - l4_start) + (replace.length - len)
      raise 'have to adjust padding but that is not implemented yet' if new_data_offset % 4 != 0

      cs_delta -= bytes.get16be(l4_start + DATA_OFFSET_OFFSET)
      bytes.setbyte(l4_start + DATA_OFFSET_OFFSET,
                    (new_data_offset / 4) << 4 | (bytes.getbyte(l4_start + DATA_OFFSET_OFFSET) & 0xf))
      cs_delta += bytes.get16be(l4_start + DATA_OFFSET_OFFSET)
    end

    checksum = bytes.byteslice(l4_start + CHECKSUM_OFFSET, 2).unpack1('n')
    checksum = IP.checksum_adjust(checksum, cs_delta)
    bytes.set16be(l4_start + CHECKSUM_OFFSET, checksum)

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

  def apply(cs_delta)
    # ICMP does not use pseudo headers
  end

  def self.recalculate_checksum(packet)
    packet.bytes.set16be(packet.l4_start + 2, 0)
    checksum = IP.checksum(packet.bytes, packet.l4_start)
    checksum = IP.checksum_adjust(checksum, packet.version.icmp_cs_delta(packet))
    packet.bytes.set16be(packet.l4_start + 2, checksum)
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

    port = @packet.bytes.get16be(@packet.l4_start + 4)
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

  def apply(cs_delta)
    @packet.bytes.set16be(@packet.l4_start + 4, @is_req ? @src_port : @dest_port)
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

  def apply(cs_delta)
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
    packet.apply
    @tundev.syswrite(packet.bytes)
  end
end
