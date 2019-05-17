@echo off
REM Filters .pcapng files using the filter passed as parameter
set tshark_path="C:\Program Files\Wireshark\tshark.exe"

REM check the number of arguments
set count=0
for %%x in (%*) do Set /A count+=1

IF %count%==3 (
    %tshark_path% -2 -nr %1 -R %3 -T json >%2
) ELSE (
    ECHO Usage: tshark_filtering.cmd input_pcap_file output_pcap_file filter
)
