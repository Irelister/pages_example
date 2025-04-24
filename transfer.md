index=bro sourcetype=corelight_conn src_ip="146.65.235.*" dest_country!=US 
| table ts src_ip src_ip_hostname src_port src_mac dest_ip dest_ip_hostname dest_port dst_mac dest_country bytes_in bytes_out 
| dedup dest_ip src_ip


index=bro sourcetype=corelight_conn src_ip="146.65.235.*" dest_country!=US 
| table ts src_ip src_ip_hostname src_port src_mac dest_ip dest_ip_hostname dest_port dst_mac dest_country bytes_in bytes_out 
| dedup dest_ip src_ip
