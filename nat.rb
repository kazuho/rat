require "./tun"
require "./nattable"

GLOBAL_ADDR = "\xc0\xa8\x0\x89".b
$tcp_table = SymmetricNATTable.new("tcp")
$tcp_table.idle_timeout = 300
$tcp_table.global_ports.push *(9000 .. 9099)
$udp_table = ConeNATTable.new("udp")
$udp_table.idle_timeout = 30
$udp_table.global_ports.push *(9000 .. 9999)

def is_egress(packet)
    packet.dest_addr != GLOBAL_ADDR
end

$tun = Tun.new("rat")

def doit()
    packet = $tun.read()
    if packet.l4
        if packet.l4.is_a?(TCP)
            table = $tcp_table
        elsif packet.l4.is_a?(UDP)
            table = $udp_table
        end
        if table
            if is_egress(packet)
                global_port = table.lookup_egress(packet)
                if global_port.nil?
                    puts "#{table.name}:no empty port"
                else
                    packet.src_addr = GLOBAL_ADDR
                    packet.l4.src_port = global_port
                    packet.apply
                    $tun.write(packet)
                end
            else
                tuple = table.lookup_ingress(packet)
                if tuple
                    packet.dest_addr = tuple.local_addr
                    packet.l4.dest_port = tuple.local_port
                    packet.apply
                    $tun.write(packet)
                else
                    puts "#{table.name}:drop ingress to port #{packet.l4.dest_port}"
                end
            end
        end
    end
end

loop do
    doit()
end
