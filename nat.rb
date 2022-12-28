require "./tun"

class Nat
    attr_accessor :global_addr, :tcp_table, :udp_table, :icmp_echo_table

    def initialize(devname)
        @tun = Tun.new(devname)
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
                if entry.bytes_sent < 200 && packet.l4.is_a?(TCP) && packet.bytes.length >= 100 && entry.stash["first-packet"].nil?
                    entry.stash["first-packet"] = packet.bytes
                end
                entry.packets_sent += 1
                entry.bytes_sent += packet.bytes.length
                packet.src_addr = @global_addr
                packet.l4.src_port = entry.global_port
                packet.apply
                @tun.write(packet)
            else
                puts "#{table.name}:no empty port"
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
                puts "#{table.name}:drop ingress to port #{packet.l4.dest_port}"
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

