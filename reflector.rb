require "./tun"

TRUE_ADDR = "\xa\1\2\3".b
FAKE_ADDR = "\xa\1\2\4".b

tun = Tun.new("tap-e")
loop do
    packet = tun.read()
    if packet.l3 and packet.l4
        if packet.l3.src_addr == TRUE_ADDR and packet.l3.dest_addr == FAKE_ADDR
            packet.l3.src_addr = FAKE_ADDR
            packet.l3.dest_addr = TRUE_ADDR
            packet.apply
            tun.write(packet)
        end
    end
end
