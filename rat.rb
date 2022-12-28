require "rackup"
require "async/scheduler"
require "falcon"
require "rack/handler/falcon"
require "irb"
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

scheduler = Async::Scheduler.new
Fiber.set_scheduler(scheduler)

Fiber.schedule do
    loop do
        nat.run
    end
end

def load_webif(nat)
    puts "loading webif.rb..."
    begin
        $webif = eval(File.open("webif.rb").read).call(nat)
    rescue => e
        print e.full_message(:highlight => false)
    rescue SyntaxError => e
        print e.full_message(:highlight => false)
    end
end

load_webif(nat)
Signal.trap("HUP") do
    load_webif(nat)
end

Fiber.schedule do
    webapp = Proc.new do |env|
        $webif.call(env)
    end
    Rack::Handler::Falcon.run(webapp, :Host => '0.0.0.0', :Port => 8080)
end

Fiber.schedule do
    $nat = nat
    IRB.start(__FILE__)
    exit
end
