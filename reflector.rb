# How to setup:
# sudo ip tuntap add dev tap-e mode tun user <username>
# sudo ip addr add 10.1.2.3/32 dev tap-e
# sudo ip link set tap-e up
# sudo ip route add 10.1.2.0/24 via 10.1.2.3

require "./tun"

TRUE_ADDR = "\xa\1\2\3".b
FAKE_ADDR = "\xa\1\2\4".b

tun = Tun.new("tap-e")
loop do
    packet = tun.read()
    if packet and packet.l4
        if packet.src_addr == TRUE_ADDR and packet.dest_addr == FAKE_ADDR
            packet.src_addr = FAKE_ADDR
            packet.dest_addr = TRUE_ADDR
            if packet.l4.is_a?(ICMPDestUnreach)
                packet.l4.orig_src_addr = TRUE_ADDR
                packet.l4.orig_dest_addr = FAKE_ADDR
            end
            packet.apply
            tun.write(packet)
        end
    end
end
