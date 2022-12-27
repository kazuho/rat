require "./tun"
require "./nattable"

class Rat
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
            global_port = table.lookup_egress(packet)
            if global_port.nil?
                puts "#{table.name}:no empty port"
            else
                packet.src_addr = @global_addr
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
        end
        return if table.nil?

        tuple = table.lookup_ingress3(packet.l4.original.l4.src_port, packet.l4.original.dest_addr, packet.l4.original.l4.dest_port)
        if tuple.nil?
            puts "drop ICMP destination unreachable to port #{packet.l4.original.l4.src_port}"
            return
        end

        packet.l4.original.src_addr = tuple.local_addr
        packet.l4.original.l4.src_port = tuple.local_port
        packet.dest_addr = tuple.local_addr

        packet.apply
        @tun.write(packet)
    end
end

rat = Rat.new("rat")

rat.global_addr = "\xc0\xa8\x0\x89".b

rat.tcp_table = SymmetricNATTable.new("tcp")
rat.tcp_table.idle_timeout = 300
rat.tcp_table.global_ports.push *(9000 .. 9099)

rat.udp_table = ConeNATTable.new("udp")
rat.udp_table.idle_timeout = 30
rat.udp_table.global_ports.push *(9000 .. 9999)

rat.icmp_echo_table = SymmetricNATTable.new("icmp-echo")
rat.icmp_echo_table.idle_timeout = 30
rat.icmp_echo_table.global_ports.push *(9000 .. 9999)

loop do
    rat.run()
end
