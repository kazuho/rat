require "irb"
require "json"
require "rackup"
require "./tun"
require "./nat"
require "./nattable"

if ENV["RAT_USE_FIBER"]
    require "async/scheduler"
    require "falcon"
    require "rack/handler/falcon"

    Fiber.set_scheduler(Async::Scheduler.new)
    def spawn_thread(last = false)
        Fiber.schedule do
            yield
        end
    end
    def rack_handler()
        Rack::Handler::Falcon
    end
else
    require "webrick"

    def spawn_thread(last = false)
        if last
            yield
        else
            Thread.new do
                yield
            end
        end
    end
    def rack_handler()
        Rackup::Handler::WEBrick
    end
end

$nat = Nat.new("rat")

# global address is 192.168.0.137
$nat.global_addr = "\xc0\xa8\x0\x89".b

# create TCP, UDP, ICMP Echo tables
$nat.tcp_table = SymmetricNATTable.new("tcp")
$nat.tcp_table.idle_timeout = 300
$nat.udp_table = ConeNATTable.new("udp")
$nat.udp_table.idle_timeout = 30
$nat.icmp_echo_table = SymmetricNATTable.new("icmp-echo")
$nat.icmp_echo_table.idle_timeout = 30

# setup ports and logger for each table
for table in [$nat.tcp_table, $nat.udp_table, $nat.icmp_echo_table]
    table.global_ports.push *(9000 .. 9999)
    table.get_logfp = Proc.new do
        if $logfp.nil?
            $logfp = open("rat.log", "a")
        end
        $logfp
    end
end

# the nat thread (that restarts itself upon exception)
spawn_thread do
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
spawn_thread do
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
    rack_handler.run(webapp, :Host => '0.0.0.0', :Port => 8080)
end

# upon SIGHUP, reset logger and webif state so that they would be reinitialized
Signal.trap("HUP") do
    $logfp = nil
    $webif = nil
end

# start IRB on the main thread
spawn_thread(true) do
    IRB.start(__FILE__)
end
