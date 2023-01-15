# frozen_string_literal: true

class Nat
  attr_accessor :global_addr, :tcp_table, :udp_table, :icmp_echo_table

  def egress?(packet)
    packet.dest_addr != @global_addr
  end

  def transform(packet)
    return unless packet&.l4

    case packet.l4
    when TCP
      table = @tcp_table
    when UDP
      table = @udp_table
    when ICMPEcho
      table = @icmp_echo_table
    when ICMPError
      return handle_icmp_error(packet) unless egress?(packet)
    end
    return if table.nil?

    if egress?(packet)
      entry = table.lookup_egress(packet)
      return unless entry

      entry.packets_sent += 1
      entry.bytes_sent += packet.bytes.size
      packet.src_addr = @global_addr
      packet.l4.src_port = entry.global_port
    else
      entry = table.lookup_ingress(packet)
      return unless entry

      entry.packets_received += 1
      entry.bytes_received += packet.bytes.size
      packet.dest_addr = entry.local_addr
      packet.l4.dest_port = entry.local_port
    end

    packet
  end

  def handle_icmp_error(packet)
    case packet.l4.original.l4
    when TCP
      table = @tcp_table
    when UDP
      table = @udp_table
    when ICMPEcho
      table = @icmp_echo_table
    end
    return if table.nil?

    entry = table.icmp_lookup_ingress(packet.l4.original.l4.src_port, packet.l4.original.dest_addr,
                                      packet.l4.original.l4.dest_port)
    return if entry.nil?

    entry.packets_received += 1
    entry.bytes_received += packet.bytes.size
    packet.l4.original.src_addr = entry.local_addr
    packet.l4.original.l4.src_port = entry.local_port
    packet.dest_addr = entry.local_addr

    packet
  end

  def webapp(env)
    if @webapp.nil?
      begin
        @webapp = eval(File.open('webif.rb').read).call(self)
      rescue StandardError => e
        print e.full_message(highlight: false)
      rescue SyntaxError => e
        print e.full_message(highlight: false)
      end
    end
    if @webapp
      @webapp.call(env)
    else
      [500, { 'content-type' => 'text/plain; charset=utf-8' }, ['webif broken at the moment']]
    end
  end

  def reload_webapp
    @webapp = nil
  end
end
