require "./tun"

class Nat
    attr_accessor :global_addr, :tcp_table, :udp_table, :icmp_echo_table, :on_no_empty_port, :on_drop_ingress

    def initialize(devname)
        @tun = Tun.new(devname)
        @on_no_empty_port = Proc.new do end
        @on_drop_ingress = Proc.new do end
    end

    def is_egress(packet)
        packet.dest_addr != @global_addr
    end

    def run()
        packet = @tun.read()
        if packet && packet.l4
            handle_packet(packet)
        end
    end

    def handle_packet(packet)
        if packet.l4.is_a?(TCP)
            table = @tcp_table
        elsif packet.l4.is_a?(UDP)
            table = @udp_table
        elsif packet.l4.is_a?(ICMPEcho)
            table = @icmp_echo_table
        elsif packet.l4.is_a?(ICMPDestUnreach) && !is_egress(packet)
            handle_destunreach(packet)
            return
        end
        return if table.nil?

        if is_egress(packet)
            entry = table.lookup_egress(packet)
            if entry
                entry.packets_sent += 1
                entry.bytes_sent += packet.bytes.length
                packet.src_addr = @global_addr
                packet.l4.src_port = entry.global_port
                packet.apply
                @tun.write(packet)
            else
                @on_no_empty_port.call(self, packet, table)
            end
        else
            entry = table.lookup_ingress(packet)
            if entry
                entry.packets_received += 1
                entry.bytes_received += packet.bytes.length
                packet.dest_addr = entry.local_addr
                packet.l4.dest_port = entry.local_port
                packet.apply
                @tun.write(packet)
            else
                @on_drop_ingress.call(self, packet, table)
            end
        end
    end

    def handle_destunreach(packet)
        if packet.l4.original.l4.is_a?(TCP)
            table = @tcp_table
        elsif packet.l4.original.l4.is_a?(UDP)
            table = @udp_table
        end
        return if table.nil?

        entry = table.lookup_ingress3(packet.l4.original.l4.src_port, packet.l4.original.dest_addr, packet.l4.original.l4.dest_port)
        if entry.nil?
            puts "drop ICMP destination unreachable to port #{packet.l4.original.l4.src_port}"
            return
        end

        entry.packets_received += 1
        entry.bytes_received += packet.bytes.length
        packet.l4.original.src_addr = entry.local_addr
        packet.l4.original.l4.src_port = entry.local_port
        packet.dest_addr = entry.local_addr

        packet.apply
        @tun.write(packet)
    end
end

