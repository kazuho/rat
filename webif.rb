Proc.new do |nat|
    puts "generating webif"
    Proc.new do |env|
        resp = "<style type='text/css'>body {font-family: monospace} th, td {padding: 0 1em}</style>"
        for table in [nat.tcp_table, nat.udp_table, nat.icmp_echo_table]
            table.gc
            resp += "<h3>#{table.name} (#{table.size}):</h3>\n"
            if table.size != 0
                resp += "<table>\n"
                resp += "<tr><th>local</th><th>remote</th><th>sni</th><th>port</th><th>duration</th><th>idle</th><th>pkts sent</th><th>bytes sent</th><th>pkts recv</th><th>bytes recv</th></tr>\n"
                table.each do |entry|
                    first_packet = entry.stash["first-packet"]
                    if first_packet
                        first_packet = first_packet[40 .. ] # strip IPv4 and TCP header
                        puts "first_packet:#{first_packet.length}"
                        while first_packet.match(/\0\0\0(.)\0(.)\0\0(.)/m)
                            ext_size = $1.ord
                            list_size = $2.ord
                            name_size = $3.ord
                            puts "#{ext_size},#{list_size},#{name_size}"
                            if ext_size == list_size + 2 && list_size == name_size + 3
                                sni = $'[0 .. name_size]
                                break
                            end
                        end
                    end
                    resp += "<tr>"
                    resp += "<td>#{IP.addr_to_s(entry.local_addr)}:#{entry.local_port}</td>"
                    resp += "<td>#{IP.addr_to_s(entry.remote_addr)}:#{entry.remote_port}</td>"
                    resp += "<td>#{sni ? sni : '-'}</td>"
                    resp += "<td align='right'>#{entry.global_port}</td>"
                    resp += "<td align='right'>#{Time.now.to_i - entry.create_at}</td>"
                    resp += "<td align='right'>#{Time.now.to_i - entry.last_access}</td>"
                    resp += "<td align='right'>#{entry.packets_sent}</td>"
                    resp += "<td align='right'>#{entry.bytes_sent}</td>"
                    resp += "<td align='right'>#{entry.packets_received}</td>"
                    resp += "<td align='right'>#{entry.bytes_received}</td>"
                    resp += "</tr>\n"
                end
                resp += "</table>\n"
            end
        end
        [200, {"Content-Type" => "text/html; charset=utf-8"}, [resp]]
    end
end
