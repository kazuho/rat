Proc.new do |nat|
    puts "generating webif"
    Proc.new do |env|
        resp = "<style type='text/css'>body {font-family: monospace} th, td {padding: 0 1em}</style>"
        for table in [nat.tcp_table, nat.udp_table, nat.icmp_echo_table]
            resp += "<h3>#{table.name} (#{table.size}):</h3>\n"
            if table.size != 0
                resp += "<table>\n"
                resp += "<tr><th>local</th><th>remote</th><th>port</th><th>idle</th></tr>\n"
                table.each do |tuple|
                    resp += "<tr>"
                    resp += "<td>#{IP.addr_to_s(tuple.local_addr)}:#{tuple.local_port}</td>"
                    resp += "<td>#{IP.addr_to_s(tuple.remote_addr)}:#{tuple.remote_port}</td>"
                    resp += "<td align='right'>#{tuple.global_port}</td>"
                    resp += "<td align='right'>#{Time.now.to_i - tuple.last_access}</td>"
                    resp += "</tr>\n"
                end
                resp += "</table>\n"
            end
        end
        [200, {"Content-Type" => "text/html; charset=utf-8"}, [resp]]
    end
end
