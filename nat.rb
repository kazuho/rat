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
        elsif packet.l4.is_a?(ICMPWithOriginalPacket) && !is_egress(packet)
            handle_icmp_with_original_packet(packet)
            return
        end
        return if table.nil?

        if is_egress(packet)
            entry = table.lookup_egress(packet)
            if entry
                entry.packets_sent += 1
                entry.bytes_sent += packet.bytes.length
                packet.src_addr = @global_addr
                packet.l4.src_port = entry.global_port
                packet.apply
                @tun.write(packet)
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
            end
        end
    end

    def handle_icmp_with_original_packet(packet)
        if packet.l4.original.l4.is_a?(TCP)
            table = @tcp_table
        elsif packet.l4.original.l4.is_a?(UDP)
            table = @udp_table
        elsif packet.l4.original.l4.is_a?(ICMPEcho)
            table = @icmp_echo_table
        end
        return if table.nil?

        entry = table.icmp_lookup_ingress(packet.l4.original.l4.src_port, packet.l4.original.dest_addr, packet.l4.original.l4.dest_port)
        if entry.nil?
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

    def self.webapp
        klass = Class.new do
            def call(env)
                if @app.nil?
                    begin
                        @app = eval(File.open("webif.rb").read).call($nat)
                    rescue => e
                        print e.full_message(:highlight => false)
                    rescue SyntaxError => e
                        print e.full_message(:highlight => false)
                    end
                end
                if @app
                    @app.call(env)
                else
                    [500, {"content-type" => "text/plain; charset=utf-8"}, ["webif broken at the moment"]]
                end
            end
            def reload()
                @app = nil
            end
        end
        klass.new
    end
end

