require "./tun"
require "./nat"
require "./nattable"

nat = Nat.new("rat")

nat.global_addr = "\xc0\xa8\x0\x89".b

nat.tcp_table = SymmetricNATTable.new("tcp")
nat.tcp_table.idle_timeout = 300
nat.tcp_table.global_ports.push *(9000 .. 9099)

nat.udp_table = ConeNATTable.new("udp")
nat.udp_table.idle_timeout = 30
nat.udp_table.global_ports.push *(9000 .. 9999)

nat.icmp_echo_table = SymmetricNATTable.new("icmp-echo")
nat.icmp_echo_table.idle_timeout = 30
nat.icmp_echo_table.global_ports.push *(9000 .. 9999)

loop do
    nat.run()
end
