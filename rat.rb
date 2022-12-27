require "./tun"
require "./nattable"

class Rat
    GLOBAL_ADDR = "\xc0\xa8\x0\x89".b

    attr_accessor :tcp_table, :udp_table, :icmp_echo_table

    def initialize()
        @tcp_table = SymmetricNATTable.new("tcp")
        @tcp_table.idle_timeout = 300
        @tcp_table.global_ports.push *(9000 .. 9099)

        @udp_table = ConeNATTable.new("udp")
        @udp_table.idle_timeout = 30
        @udp_table.global_ports.push *(9000 .. 9999)

        @icmp_echo_table = SymmetricNATTable.new("icmp-echo")
        @icmp_echo_table.idle_timeout = 30
        @icmp_echo_table.global_ports.push *(9000 .. 9999)

        @tun = Tun.new("rat")
    end

    def is_egress(packet)
        packet.dest_addr != GLOBAL_ADDR
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

        if is_egress(packet)
            global_port = table.lookup_egress(packet)
            if global_port.nil?
                puts "#{table.name}:no empty port"
            else
                packet.src_addr = GLOBAL_ADDR
                packet.l4.src_port = global_port
                packet.apply
                @tun.write(packet)
            end
        else
            tuple = table.lookup_ingress(packet)
            if tuple
                packet.dest_addr = tuple.local_addr
                packet.l4.dest_port = tuple.local_port
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
        else
            return
        end
        entry = table.lookup_ingress3(packet.l4.original.l4.src_port, packet.l4.original.dest_addr, packet.l4.original.l4.dest_port)
        if entry.nil?
            puts "drop ICMP destination unreachable to port #{packet.l4.original.l4.src_port}"
            return
        end

        packet.l4.original.src_addr = entry.local_addr
        packet.l4.original.l4.src_port = entry.local_port
        packet.dest_addr = entry.local_addr

        packet.apply
        @tun.write(packet)
    end
end

rat = Rat.new
loop do
    rat.run()
end
