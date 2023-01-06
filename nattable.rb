# frozen_string_literal: true

class NATTable
  attr_accessor :name, :idle_timeout, :global_ports, :get_logfp

  class Entry
    attr_accessor :prev, :next, :create_at, :last_access, :local_addr, :local_port, :global_port, :remote_addr,
                  :remote_port, :packets_sent, :packets_received, :bytes_sent, :bytes_received

    def initialize
      @create_at = Time.now.to_i
      @packets_sent = 0
      @packets_received = 0
      @bytes_sent = 0
      @bytes_received = 0
    end

    def link(anchor)
      @last_access = Time.now.to_i
      anchor.prev.next = self
      self.prev = anchor.prev
      anchor.prev = self
      self.next = anchor
    end

    def unlink
      prev.next = self.next
      self.next.prev = prev
      prev = nil
      self.next = nil
    end
  end

  def initialize(name)
    @name = name
    @anchor = Entry.new
    @anchor.prev = @anchor
    @anchor.next = @anchor
    @locals = {}  # index of entries with key: local_addr + local_port + remote_addr + remote_port
    @remotes = {} # index of entries with key: global_port + remote_addr + remote_port
    @global_ports = []
    @get_logfp = proc {}
  end

  def lookup_egress(packet)
    entry = @locals[local_key_from_packet(packet)]

    if entry.nil?
      local_addr = packet.src_addr
      remote_addr = packet.dest_addr
      l4 = packet.l4
      local_port = l4.src_port
      remote_port = l4.dest_port
      global_port = empty_port(remote_addr, remote_port)
      if global_port.nil?
        log('no_empty_port', local_addr, local_port, nil, remote_addr, remote_port, { 'table_size' => size })
        return nil
      end
      entry = _insert(local_addr, local_port, global_port, remote_addr, remote_port)
      log('insert', local_addr, local_port, global_port, remote_addr, remote_port, { 'table_size' => size })
    else
      entry.unlink
      entry.link(@anchor)
    end

    entry
  end

  def lookup_ingress(packet)
    entry = @remotes[remote_key_from_packet(packet)]
    log('ingress_not_found', nil, nil, packet.l4.dest_port, packet.src_addr, packet.l4.src_port) if entry.nil?
    entry
  end

  def icmp_lookup_ingress(global_port, remote_addr, remote_port)
    entry = @remotes[remote_key_from_tuple(global_port, remote_addr, remote_port)]
    log('icmp_ingress_not_found', nil, nil, global_port, remote_addr, remote_port) if entry.nil?
    entry
  end

  def empty?
    @locals.empty?
  end

  def size
    @locals.size
  end

  def each
    entry = @anchor.next
    while entry != @anchor
      n = entry.next
      yield entry
      entry = n
    end
  end

  def gc
    items_before = Time.now.to_i - idle_timeout
    while @anchor.next != @anchor && @anchor.next.last_access < items_before
      entry = @anchor.next
      _gc_entry(entry)
      log('delete', entry.local_addr, entry.local_port, entry.global_port, entry.remote_addr, entry.remote_port,
          {
            'create' => entry.create_at,
            'last_access' => entry.last_access,
            'packets_sent' => entry.packets_sent,
            'packets_received' => entry.packets_received,
            'bytes_sent' => entry.bytes_sent,
            'bytes_received' => entry.bytes_received,
            'table_size' => size
          })
    end
  end

  def _gc_entry(entry)
    entry.unlink
    @locals.delete(local_key_from_tuple(entry.local_addr, entry.local_port, entry.remote_addr, entry.remote_port))
    @remotes.delete(remote_key_from_tuple(entry.global_port, entry.remote_addr, entry.remote_port))
  end

  def _insert(local_addr, local_port, global_port, remote_addr, remote_port)
    entry = Entry.new
    entry.local_addr = local_addr
    entry.local_port = local_port
    entry.global_port = global_port
    entry.remote_addr = remote_addr
    entry.remote_port = remote_port

    entry.link(@anchor)
    @locals[local_key_from_tuple(local_addr, local_port, remote_addr, remote_port)] = entry
    @remotes[remote_key_from_tuple(global_port, remote_addr, remote_port)] = entry

    entry
  end

  def log(event, local_addr, local_port, global_port, remote_addr, remote_port, others = nil)
    logfp = @get_logfp.call
    return unless logfp

    hash = {
      'at' => Time.now.to_i,
      'event' => event,
      'table' => @name,
      'local_addr' => local_addr ? IP.addr_to_s(local_addr) : nil,
      'local_port' => local_port,
      'global_port' => global_port,
      'remote_addr' => IP.addr_to_s(remote_addr),
      'remote_port' => remote_port
    }
    hash.merge! others if others
    logfp.syswrite "#{JSON.fast_generate(hash)}\n"
  end
end

class SymmetricNATTable < NATTable
  def empty_port(remote_addr, remote_port)
    gc
    20.times do
      test_port = @global_ports[rand(@global_ports.length)]
      return test_port unless @remotes[remote_key_from_tuple(test_port, remote_addr, remote_port)]
    end
    nil
  end

  def local_key_from_packet(packet)
    l3_tuple = packet.tuple
    l3_tuple_size = l3_tuple.size

    b = IO::Buffer.new(l3_tuple_size + 4)
    b.copy(l3_tuple)
    b.copy(packet.l4.tuple, l3_tuple_size)

    b.get_string
  end

  def local_key_from_tuple(local_addr, local_port, remote_addr, remote_port)
    addr_size = local_addr.size

    b = IO::Buffer.new(addr_size * 2 + 4)
    b.copy(local_addr)
    b.copy(remote_addr, addr_size)
    b.set_value(:U16, addr_size * 2, local_port)
    b.set_value(:U16, addr_size * 2 + 2, remote_port)

    b.get_string
  end

  def remote_key_from_packet(packet)
    src_addr = packet.src_addr
    addr_size = src_addr.size

    b = IO::Buffer.new(addr_size + 4)
    b.copy(src_addr)
    b.copy(packet.l4.tuple, addr_size)

    b.get_string
  end

  def remote_key_from_tuple(global_port, remote_addr, remote_port)
    addr_size = remote_addr.size

    b = IO::Buffer.new(addr_size + 4)
    b.copy(remote_addr)
    b.set_value(:U16, addr_size, remote_port)
    b.set_value(:U16, addr_size + 2, global_port)

    b.get_string
  end
end

class ConeNATTable < NATTable
  def empty_port(_remote_addr, _remote_port)
    gc
    @empty_ports = global_ports.dup if @empty_ports.nil?
    return nil if @empty_ports.empty?

    @empty_ports.shift
  end

  def _gc_entry(entry)
    super(entry)
    @empty_ports.push entry.global_port
  end

  def local_key_from_packet(packet)
    local_key_from_tuple(packet.src_addr, packet.l4.src_port, nil, nil)
  end

  def local_key_from_tuple(local_addr, local_port, _remote_addr, _remote_port)
    addr_size = local_addr.size

    b = IO::Buffer.new(addr_size + 2)
    b.copy(local_addr)
    b.set_value(:U16, addr_size, local_port)

    b.get_string
  end

  def remote_key_from_packet(packet)
    packet.l4.dest_port
  end

  def remote_key_from_tuple(global_port, _remote_addr, _remote_port)
    global_port
  end
end
