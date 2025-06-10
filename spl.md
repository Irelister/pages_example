<details><summary>Bro Query</summary>
  
```plaintext
index=bro sourcetype=corelight_conn earliest= latest=now()
```
</details>

<details><summary>Summary Index Query</summary>
  
```plaintext
index=central_summary source=summary_conn_dest earliest= latest=now()
```
</details>

<details><summary>List all Indexes</summary>
  
```plaintext
| eventcount summarize=false index=* | dedup index | fields index
```
</details>

<details><summary>List Index Sources/Types w/ Timestamps</summary>
  
```plaintext
| metadata type="sourcetypes" index="bro"
| fieldformat firstTime=strftime(firstTime, "%m/%d/%y %H:%M:%S")
| fieldformat lastTime=strftime(lastTime, "%m/%d/%y %H:%M:%S")
```
</details>

<details><summary>List Fields for a Source/type</summary>
  
```plaintext
index="bro" sourcetype="corelight_bacnet"
| fieldsummary
| fields field

index="asset_summary" source="summary_conn_allowed"
| fieldsummary
| fields field
```
</details>

<details><summary>All Conns for an IP</summary>
  
```plaintext
index="bro" sourcetype="corelight_conn" dest_ip=<IP> OR src_ip=<IP> earliest=<first_seen> latest=<last_seen>
| table src_ip, src_port, orig_bytes, dest_ip, dest_port, dest_bytes
```
</details>

<details><summary>Domain Controllers</summary>
  
```plaintext
index=bro sourcetype=corelight_kerberos request_type=AS success=true
| table app, dest_ip 
| dedup app, dest_ip
```
</details>

<details><summary>Hostname via DNS</summary>
  
```plaintext
index=bro sourcetype=corelight_dns answer=<ip>
| table query, answer
| head 15
```
</details>

<details><summary>Internal Web Servers</summary>
  
```plaintext
index=bro sourcetype IN (corelight_http, corelight_ssl) is_dest_internal_ip=true
| dedup dest_port
| table dest_ip, dest_port, sum(bytes_out), url_domain, server_name, ja4s
```
</details>

<details><summary>Network DHCP Info</summary>
  
```plaintext
index=bro sourcetype=corelight_dhcp
| rename client_fqdn as dhcp_server
| rename dest_dns as assigned_dns
| table assigned_addr, dest_mac, lease_time, domain, dhcp_server, assigned_dns
```
</details>

<details><summary>Frequent Outbound Connections to Consumer ISP Ranges</summary>
  
```plaintext
index=bro sourcetype=corelight_conn dest_port IN (80 443 8080)
| lookup asn_by_ip ip as id.resp_h OUTPUT org 
| search org="Comcast" OR org="AT&T" OR org="Charter" OR org="Verizon" 
| stats count by id.orig_h, id.resp_h, org 
```
</details>

<details><summary>Multiple Domains Resolving to Same IP</summary>
  
```plaintext
index=central_summary source=summary_dns_with_answers 
| stats dc(query) as domain_count by answer 
| where domain_count > 10 
```
</details>

<details><summary>Rare JA3/JA3S TLS Fingerprints</summary>
  
```plaintext
index=central_summary source=summary_ssl 
| stats count by ja3, ja3s, dest_ip 
| where count < 5 
```
</details>

<details><summary>Unusual HTTP Hosts or Repeating POST Requests</summary>
  
```plaintext
index=bro sourcetype=corelight_http 
| search method=POST 
| stats count by src_ip, dest_ip, host_header, uri, user_agent 
| where count > 20 
```
</details>

<details><summary>High-Volume, Long-Lived Peer-to-Peer Connections</summary>
  
```plaintext
index=bro sourcetype=corelight_conn 
| search duration > 300 
| stats count by src_ip, dest_ip, duration, service 
| where count > 20 
```
</details>

<details><summary>Suspicious File Transfers Over SMB</summary>
  
```plaintext
index=central_summary source=summary_smb_files filename_with_extension IN ("lsass.dmp" *.dmp "procdump.exe") 
| stats count by src_ip, dest_ip, filename_with_extension, action 
```
</details>

<details><summary>Execution or Transfer of Credential Dumping Tools</summary>
  
```plaintext
index=central_summary source=summary_http_address uri IN (*procdump* *mimikatz* *lsass* *comsvcs*) 
| stats count by src_ip, dest_ip, uri 

Index=bro sourcetype=corelight_http uri IN (*procdump* *mimikatz* *lsass* *comsvcs*) 
| stats count by src_ip, dest_ip, uri, user_agent 
```
</details>

<details><summary>Remote Access to LSASS via RPC or SAMR</summary>
  
```plaintext
index=bro sourcetype=corelight_rpc 
| search program IN ("samr", "lsarpc") 
| stats count by src_ip, dest_ip, call 
```
</details>

<details><summary>Suspicious SMB Uploads from Admin Workstations</summary>
  
```plaintext
index=bro sourcetype=corelight_smb_cmd command="WRITE"
| stats count by src_ip, dest_ip, command 
```
</details>

<details><summary>Dump Files Exfiltrated Over HTTP</summary>
  
```plaintext
index=central_summary source=summary_http_address uri IN (*.dmp *.zip) 
| stats count by src_ip, dest_ip, uri 
```
</details>
##T1564 Hide Artifacts
<details><summary>Detect File Transfers with Suspicious or Hidden Filenames</summary>
  
```plaintext
index=zeek sourcetype=zeek:files 
| where isnull(extracted) AND (filename LIKE ".%" OR filename IN ("thumbs.db", "desktop.ini")) 
| eval risk="Possible hidden file transfer"
| table _time, uid, source, destination, filename, mime_type, risk
```
</details>

<details><summary>Detect Executable Files from Suspicious Directories via SMB</summary>
  
```plaintext
index=zeek sourcetype=zeek:smb_files 
| where filename LIKE "%.exe" AND (filename LIKE "%\\$Recycle.Bin\\%" OR filename LIKE "%\\Temp\\%") 
| eval risk="Executable file in suspicious hidden folder"
| table _time, id_orig_h, id_resp_h, filename, action, seen_bytes, risk
```
</details>

<details><summary>Detect Long SSH Sessions</summary>
  
```plaintext
index=zeek sourcetype=zeek:ssh 
| search auth_success=true 
| join type=inner uid [ search index=zeek sourcetype=zeek:conn ] 
| where service=="ssh" AND duration>300 
| eval risk="Long SSH session; check for hidden or file manipulation"
| table _time, id_orig_h, id_resp_h, duration, auth_success, risk
```
</details>

<details><summary>Detect Archive Files with Suspicious Naming or Locations</summary>
  
```plaintext
index=zeek sourcetype=zeek:files 
| where mime_type IN ("application/zip", "application/x-rar-compressed") AND filename LIKE "%.%" 
| search filename=".%" OR filename LIKE "%\\Temp\\%" 
| eval risk="Possible hidden archive"
| table _time, id_orig_h, id_resp_h, filename, mime_type, risk
```
</details>

<details><summary>Look for Uncommon File Extensions Used Over HTTP or SMB</summary>
  
```plaintext
index=zeek sourcetype=zeek:files 
| where mime_type="application/octet-stream" AND NOT filename LIKE "%.exe" AND NOT filename LIKE "%.dll" 
| eval risk="Unusual binary transfer - possible renamed executable or payload"
| table _time, filename, mime_type, id_orig_h, id_resp_h, risk
```
</details>

Combine weird transfer with off process creations if possible.  
Look for NTFS Alternate Data streams. Detectable if SMB logs show file::$DATA in the filename.

<details><summary></summary>
  
```plaintext

```
</details>

<details><summary></summary>
  
```plaintext

```
</details>

<details><summary></summary>
  
```plaintext

```
</details>

<details><summary></summary>
  
```plaintext

```
</details>
