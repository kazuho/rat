require "./tun"

class BaseNAT
    attr_accessor :idle_timeout, :global_ports

    class Entry
        attr_accessor :prev, :next, :last_access, :local_addr, :local_port, :global_port, :remote_addr, :remote_port

        def link(anchor)
            @last_access = Time.now.to_i
            anchor.prev.next = self
            self.prev = anchor.prev
            anchor.prev = self
            self.next = anchor
        end

        def unlink()
            prev.next = self.next
            self.next.prev = prev
            prev = nil
            self.next = nil
        end
    end

    def initialize()
        @anchor = Entry.new
        @anchor.prev = @anchor
        @anchor.next = @anchor
        @locals = {}  # index of entries with key: local_addr + local_port + remote_addr + remote_port
        @remotes = {} # index of entries with key: global_port + remote_addr + remote_port
        @global_ports = []
    end

    def lookup_egress(local_addr, local_port, remote_addr, remote_port)
        entry = @locals[local_key(local_addr, local_port, remote_addr, remote_port)]

        if entry.nil?
            global_port = empty_port(remote_addr, remote_port)
            if global_port.nil?
                return nil
            end
            puts "adding mapping #{IPv4.addr_to_s(local_addr)}:#{local_port}:#{IPv4.addr_to_s(remote_addr)}:#{remote_port} using #{global_port}"
            entry = _insert(local_addr, local_port, global_port, remote_addr, remote_port)
        else
            entry.unlink
            entry.link(@anchor)
        end

        entry.global_port
    end

    def lookup_ingress(global_port, remote_addr, remote_port)
        @remotes[remote_key(global_port, remote_addr, remote_port)]
    end

    def gc()
        items_before = Time.now.to_i - idle_timeout
        while @anchor.next != @anchor && @anchor.next.last_access < items_before
            puts "removing mapping remote_port=#{@anchor.next.remote_port}, global_port=#{@anchor.next.global_port}"
            _gc_entry(@anchor.next)
        end
    end

    def _gc_entry(entry)
        entry.unlink
        @locals.delete(local_key(entry.local_addr, entry.local_port, entry.remote_addr, entry.remote_port))
        @remotes.delete(remote_key(entry.global_port, entry.remote_addr, entry.remote_port))
    end

    def _insert(local_addr, local_port, global_port, remote_addr, remote_port)
        entry = Entry.new
        entry.local_addr = local_addr
        entry.local_port = local_port
        entry.global_port = global_port
        entry.remote_addr = remote_addr
        entry.remote_port = remote_port

        entry.link(@anchor)
        @locals[local_key(local_addr, local_port, remote_addr, remote_port)] = entry
        @remotes[remote_key(global_port, remote_addr, remote_port)] = entry

        entry
    end
end

class SymmetricNAT < BaseNAT
    def empty_port(remote_addr, remote_port)
        gc
        loop do
            test_port = @global_ports[rand(@global_ports.length)]
            unless @remotes[remote_key(test_port, remote_addr, remote_port)]
                return test_port
            end
        end
    end

    def local_key(local_addr, local_port, remote_addr, remote_port)
        local_addr + ":" + local_port.to_s + ":" + remote_addr + ":" + remote_port.to_s
    end

    def remote_key(global_port, remote_addr, remote_port)
       global_port.to_s + ":" + remote_addr + ":" + remote_port.to_s
    end
end

class ConeNAT < BaseNAT
    def empty_port(remote_addr, remote_port)
        if @empty_ports.nil?
            empty_ports = global_ports.dup
        end
        if empty_ports.empty?
            return nil
        end
        empty_ports.shift
    end

    def _gc_entry(entry)
        super(entry)
        empty_ports.push entry.global_port
    end

    def local_key(local_addr, local_port, remote_addr, remote_port)
        local_addr + ":" + local_port
    end

    def remote_key(global_port, remote_addr, remote_port)
       global_port
    end
end

GLOBAL_ADDR = "\xc0\xa8\x5b\xc8".b
tcp_table = SymmetricNAT.new
tcp_table.idle_timeout = 30
tcp_table.global_ports.push *(9000 .. 9100)

def is_egress(packet)
    packet.l3.dest_addr != GLOBAL_ADDR
end

tun = Tun.new("rat")

loop do
    packet = tun.read()
    if packet.l4
        if packet.l4.is_a?(TCP)
            if is_egress(packet)
                global_port = tcp_table.lookup_egress(packet.l3.src_addr, packet.l4.src_port, packet.l3.dest_addr,
                                                      packet.l4.dest_port)
                if global_port.nil?
                    puts "no empty port"
                else
                    packet.l3.src_addr = GLOBAL_ADDR
                    packet.l4.src_port = global_port
                    packet.apply
                    tun.write(packet)
                end
            else
                tuple = tcp_table.lookup_ingress(packet.l4.dest_port, packet.l3.src_addr, packet.l4.src_port)
                if tuple
                    packet.l3.dest_addr = tuple.local_addr
                    packet.l4.dest_port = tuple.local_port
                    packet.apply
                    tun.write(packet)
                end
            end
        end
    end
end
