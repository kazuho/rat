require "irb"
require "json"
require "rackup"
require "webrick"
require "./tun"
require "./nat"
require "./nattable"

$nat = Nat.new("rat")

# global address is 192.168.0.137
$nat.global_addr = "\xc0\xa8\x0\x89".b

# TCP table
$nat.tcp_table = SymmetricNATTable.new("tcp")
$nat.tcp_table.idle_timeout = 300
$nat.tcp_table.global_ports.push *(9000 .. 9099)

# UDP table
$nat.udp_table = ConeNATTable.new("udp")
$nat.udp_table.idle_timeout = 30
$nat.udp_table.global_ports.push *(9000 .. 9999)

# ICMP Echo (ping) table
$nat.icmp_echo_table = SymmetricNATTable.new("icmp-echo")
$nat.icmp_echo_table.idle_timeout = 30
$nat.icmp_echo_table.global_ports.push *(9000 .. 9999)

# loggers
def log(event, table, local_addr, local_port, global_port, remote_addr, remote_port, others = nil)
    if $logfp.nil?
        $logfp = open("rat.log", "a")
    end
    hash = {
        "at"          => Time.now.to_i,
        "event"       => event,
        "table"       => table,
        "local_addr"  => local_addr ? IP.addr_to_s(local_addr) : nil,
        "local_port"  => local_port,
        "global_port" => global_port,
        "remote_addr" => IP.addr_to_s(remote_addr),
        "remote_port" => remote_port,
    }
    if others
        hash.merge! others
    end
    $logfp.syswrite JSON.fast_generate(hash) + "\n"
end

$nat.on_no_empty_port = Proc.new do |nat, packet, table|
    log("no-empty-port", table.name, packet.src_addr, packet.l4.src_port, packet.dest_addr, packet.l4.dest_port)
end

$nat.on_drop_ingress = Proc.new do |nat, packet, table|
    log("drop-ingress", table.name, nil, nil, packet.l4.dest_port, packet.src_addr, packet.l4.dest_port)
end

for table in [$nat.tcp_table, $nat.udp_table, $nat.icmp_echo_table]
    table.on_insert = Proc.new do |table, entry, packet|
        log("insert", table.name, entry.local_addr, entry.local_port, entry.global_port, entry.remote_addr, entry.remote_port,
            {"table_size" => table.size})
    end
    table.on_delete = Proc.new do |table, entry, packet|
        log("delete", table.name, entry.local_addr, entry.local_port, entry.global_port, entry.remote_addr, entry.remote_port,
            {
                "create"           => entry.create_at,
                "last_access"      => entry.last_access,
                "packets_sent"     => entry.packets_sent,
                "packets_received" => entry.packets_received,
                "bytes_sent"       => entry.bytes_sent,
                "bytes_received"   => entry.bytes_received,
                "table_size"       => table.size,
            })
    end
end

# the nat thread (that restarts itself upon exception)
Thread.new do
    loop do
        begin
            loop do
                $nat.run
            end
        rescue => e
            p e.full_message(:highlight => false)
        end
    end
end

# webif thread
Thread.new do
    webapp = Proc.new do |env|
        if $webif.nil?
            begin
                $webif = eval(File.open("webif.rb").read).call($nat)
            rescue => e
                print e.full_message(:highlight => false)
            rescue SyntaxError => e
                print e.full_message(:highlight => false)
            end
        end
        if $webif
            $webif.call(env)
        else
            [500, {"content-type" => "text/plain; charset=utf-8"}, ["webif broken at the moment"]]
        end
    end
    Rackup::Handler::WEBrick.run(webapp, :Host => '0.0.0.0', :Port => 8080)
end

# upon SIGHUP, reset logger and webif state so that they would be reinitialized
Signal.trap("HUP") do
    $logfp = nil
    $webif = nil
end

# start IRB on the main thread
IRB.start(__FILE__)
