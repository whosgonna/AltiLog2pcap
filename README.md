# NAME

AltiLog2Pcap.exe

# DESCRIPTION

Convert SIP messages from MaxCS Trace Colleted logs to .pcap files.

# SYNOPSIS

AltiLog2Pcap.exe \[-i input\_log\_directory\] \[-o output\_File\] \[-a ip\_address\]

AltiLog2Pcap.exe -h

# USAGE

- **-i**

    **input:** This should point to the \\log directory of the extracted trace file.
    If no value is provided, then the current directory will be used.

- **-o**

    **(output)** Where the packet capture should be written.  If no value is provided, 
    then the input directory will be used.

- **-a** 

    **(address)** The LAN IP address of the MaxCS server.  The SIP logs do not explicitly
    contain this information. This program will attempt to pull the IP address out of the
    configuration data in the trace collection. In the event that an argument is not passed,
    and the program cannot find the IP address from the configuration data, then 10.100.100.100
    will be used.

# WARNINGS & CAVEATS

This program will read the AltiGen logs from a collected trace package that contain SIP messages 
(SIPMan, SIPPstnReg, and SIPKeepALive files), grab the timestamp, network information about the 
message, and the messages themselves, and write them to a .pcap file that can then be analyzed by 
Wireshark.

It is important to understand that certain parts of this data are interpoloated, as the entirety 
of the network header is not provided in the log file.  If discrepancies arise between the output
of this file, and an actual capture of network traffic, the actual capture should be seen as authoritative.

Some of the shortcomings of this program:

- -

    Ethernet addresses are strictly 22:22:22:11:11:11 for the MaxCS host and 22:22:22:22:22:22 for all
    remote endpoints.  Sorry, this information isn't in the log files at all, so it's populated only to ensure
    that the pcap format is valid.

- -

    The MaxCS server IP address is read in from the configuration data provided in the trace package.  Alternately,
    it is possible to set this value on the commandline.  If it is not provided, and AltiLog2Pcap cannot find
    the address from the config file, then 10.100.100.100 will be shown as the MaxCS address.

- -

    It's all UDP!  Even if the packet actually was TCP, we 'reconstitute' the packet as UDP in the packet capture.  The
    logs do record the packet as having been TCP, so this is something that may change in the future.
