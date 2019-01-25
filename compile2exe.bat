set ver=0.0.3

pp -cd -M IO::All -M IO::File -M IO::All::Dir -B -x -c -o .\AltiLog2pcap.exe .\AltiLog2pcap.pl
::exe_update.bat --icon .\res\oldaltigen_icon.ico --info "CompanyName=AltiGen Communications, Inc.;FileVersion=%ver%;ProductVersion=%ver%" .\AltiLog2pcap.exe
exe_update.bat --icon .\res\newaltigen_icon.ico --info "CompanyName=AltiGen Communications, Inc.;FileVersion=%ver%;ProductVersion=%ver%" .\AltiLog2pcap.exe

::Comments        CompanyName     FileDescription FileVersion
::InternalName    LegalCopyright  LegalTrademarks OriginalFilename
::ProductName     ProductVersion

:: Generate README from POD
perldoc.bat .\AltiLog2pcap.pl .\README.md