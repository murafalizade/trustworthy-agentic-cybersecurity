import re
import urllib.parse
import urllib.request

import pandas as pd
import duckdb

# Generic HTTP servers have no list API for DuckDB to glob against, so
# scrape the nginx directory index to find the actual parquet filename(s).
dir_url = "https://datasets.uwf.edu/data/UWF-HostData25/parquet/2025-07-20%20-%202025-07-27/"
with urllib.request.urlopen(dir_url) as response:
    index_html = response.read().decode()

file_urls = [
    urllib.parse.urljoin(dir_url, href)
    for href in re.findall(r'href="([^"]+\.parquet)"', index_html)
]

df = duckdb.sql(f"""
    SELECT "syslog-message", label_binary
    FROM read_parquet({file_urls!r})
    WHERE label_binary = 'True'
    LIMIT 25
""").df()

dataset = pd.DataFrame(df)
print(dataset)
# Extract column as a list of strings
log_list = df["syslog-message"].tolist()

# Join all 10 logs into a single newline-delimited raw string
raw_logs_str = "\n".join(log_list)
print(raw_logs_str)

"""
[{'conn-community_id': '1:frdTPuZkXTVsMjdyhDUeMFIDkzg=', 
'conn-conn_state': 'S0', 'conn-duration': 2.0413010120391846, 
'conn-history': 'D', 'conn-src_ip_zeek': '143.88.12.10', 'conn-src_port_zeek': 65149, 
'conn-dest_ip_zeek': '143.88.255.11', 'conn-dest_port_zeek': 514, 'conn-local_orig': False, 
'conn-local_resp': False, 'conn-missed_bytes': 0, 'conn-orig_bytes': 87855, 
'conn-orig_ip_bytes': 90375, 'conn-orig_pkts': 90, 'conn-proto': 'udp', 'conn-resp_bytes': 0, 
'conn-resp_ip_bytes': 0, 'conn-resp_pkts': 0, 'conn-service': 'syslog', 
'conn-ts': 1753127821.396125, 'conn-uid': 'CP0ZU71OlsNC5oMLw1', 
'conn-datetime': Timestamp('2025-07-21 19:57:01.396125'), 
'syslog-facility': 'USER', 'syslog-src_ip_zeek': '143.88.12.10', 
'syslog-src_port_zeek': 65149, 'syslog-dest_ip_zeek': '143.88.255.11', 'syslog-dest_port_zeek': 514, 
'syslog-message': '1 2025-07-21T12:57:00.000000-07:00 metasploitable3-win2k8 PowerShell 0 - [NXLOG@14506 Keywords="36028797018963968" 
EventType="INFO" EventID="600" Task="6" RecordNumber="71000" ThreadID="0"
 Channel="Windows PowerShell" Category="Provider Lifecycle" Opcode="Info" 
 EventReceivedTime="2025-07-21 12:57:00" SourceModuleName="in" SourceModuleType="im_msvistalog"] Provider "Alias" is Started.    
  Details:   \tProviderName=Alias  \tNewProviderState=Started    \tSequenceNumber=3    \tHostName=ConsoleHost  \tHostVersion=5.0.10586.117  \tHostId=0d80c8c0-bc7d-44bc-b75a-1bcc7f78dfde  \tHostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\attacks\\obfuscation.ps1  \tEngineVersion=  \tRunspaceId=  \tPipelineId=  \tCommandName=  \tCommandType=  \tScriptName=  \tCommandPath=  \tCommandLine=', 'syslog-proto': 'udp', 'syslog-severity': 'INFO', 'syslog-ts': 1753127821.396741, 'syslog-uid': 'CP0ZU71OlsNC5oMLw1', 'label_tactic': 'Persistence', 'label_technique': 'T1098', 'label_binary': 'True', 'label_cve': 'none'}]

"""