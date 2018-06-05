use Modern::Perl;

use IO::File;
use IO::All;
use lib './lib/';
use ATGN::PCAP;
use ATGN::PCAP::Util qw(hexdump);
use Time::Local;
use Getopt::Long;
use Pod::Usage;


my %opts;
$opts{i} = '.';

GetOptions (
    "input=s"   => \$opts{i},
    "output=s"  => \$opts{o},
	"address=s" => \$opts{a},
    "help"      => \$opts{h},
    #"verbose:s" => \$opts{v},
);

# Get help contents from the POD
if ( $opts{h} ) {
    pod2usage({
        -verbose => 2,
        -exitval => -1,
        -noperldoc => 1,
        width => 132
    });
}


$opts{o} //= "$opts{i}\\SIPLogs.pcap";

my $dirname   = $opts{i};
my $output    = $opts{o};


my $cap = ATGN::PCAP->new({file => "$output"});

my $host_ip     = $opts{a} // get_ip($dirname) // '10.100.100.100';
my $ether_local = '222222111111';
my $ether_rmt   = '222222222222';
my $loglines;


use Data::Printer;

my $dir = io($dirname);
my $files =  [ $dir->all_files ];


for my $file ( @$files ) {
	next unless ( $file->filename =~ /( ^SIPMan.*\.txt$ | ^SIPPstnReg.*txt$ | ^SIPKeepALive.*txt$ )/ix );


	my $fh = IO::File->new;
	my $file = $fh->open($file->name, "<");
	my $current;
	#my $loglines;

	while ( defined(my $line  = $fh->getline ) ) {
		if ( $line =~ /^\s\s+$/ ) {
			undef($current);
		}
		if ( 
			$line =~ m%^
			(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})\s
			(?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2}),(?<msec>\d{3})
			\(\d{1,5}\)\s\[
			(?<thread>0x[0-9a-f]{1,5}) \]\s
			\(\(\d{1,2},\d{1,6}\)\)\s #literal
			(?<protocol>UDP|TCP)\s
			(?<dir>Sent)\( (?<size1>\d{1,3}) / (?<size2>\d{1,3}) \)\s
			SrcPort\( (?<src_port>\d{1,5}) \),\s
			RmtPort\( (?<dst_port>\d{1,5}) \),\s
			RmtIP\( (?<dst_host>\d{1,3}\.\d{1,3}.\d{1,3}\.\d{1,3}) \)
			%x
			
				||
			
			$line =~ m%^
			(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})\s
			(?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2}),(?<msec>\d{3})
			\(\d{1,5}\)\s\[
			(?<thread>0x[0-9a-f]{1,5}) \]\s
			SipCallMan \s\(\d{1,5}\)\s 
			(?<dir>recv)\s
			(?<protocol>UDP|TCP)\s
			data\slen\s=\s(?<size1>\d{1,4})
			,org\s
			(?<src_host>\d{1,3}\.\d{1,3}.\d{1,3}\.\d{1,3})
			:\(
			(?<src_port>\d{1,5})
			\)\sdest\s\(
			(?<dst_port>\d{1,5}) 
			\)\safter\srecv
			%x
		) {
			undef($current);
			my $tstamp = "$+{year}$+{month}$+{day}$+{hour}$+{minute}$+{second}$+{msec}_$+{thread}";

			$loglines->{$tstamp} = {
				tstamp	  => $tstamp,
				year      => $+{year},
				month     => $+{month},
				day       => $+{day},
				minute    => $+{minute},
				second    => $+{second},
				usec      => $+{msec} * 1000,
				proto     => $+{protocol},
				dir       => $+{dir},
				size1     => $+{size1},
				size2     => $+{size2},
				dst_host  => $+{dir} eq 'Sent' ? $+{dst_host} : $host_ip,
				src_host  => $+{dir} eq 'Sent' ? $host_ip: $+{src_host} ,
				ether_src => $+{dir} eq 'Sent' ? $ether_local : $ether_rmt,
				ether_dst => $+{dir} eq 'Sent' ? $ether_rmt   : $ether_local,
				dst_port  => $+{dst_port},
				src_port  => $+{src_port},
				log       => q{},
			};
			$current = $tstamp;
		}
		elsif (
			$line !~ m%^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}%
			&&
			$current
		) {
			$loglines->{$current}->{log} .= $line;
		}
	}
}


	for my $key (sort keys %$loglines) {
		my $line = $loglines->{$key};
		
		# Get seconds from Epoch from the timestamp:
		my $ts_sec = timelocal(
			$line->{second},
			$line->{minute},
			$line->{hour},
			$line->{day},
			( $line->{month} - 1 ),
			$line->{year}
		);
		
		my $size = $line->{size1};
		if ($line->{size2}) {
			$size = $line->{size2} if ( $line->{size2} > $size );
		}
		

		my $frame = $cap->new_frame(
		ether_dst  => $line->{ether_dst},
		ether_src  => $line->{ether_src},
		ts_sec     => $ts_sec,
		ts_usec    => $line->{usec},
		src_host   => $line->{src_host},
		dst_host   => $line->{dst_host},
		src_port   => $line->{src_port},
		dst_port   => $line->{dst_port},
		origin_len => $line->{size},
		data       => $line->{log},
	);


	}


sub get_ip {
	my $logdir    = shift;
	my $ip;
	my $traceconf = "$dirname" . '\..\Config\altiserv\db\localsite\Repository.xml';

	my $conffh   = IO::File->new;
	my $conffile = $conffh->open($traceconf, '<');
	while( defined( my $line = $conffh->getline ) ) {
		if ( $line =~ m#<IPAddress\s class-='java.lang.String'>
				(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
				</IPAddress>#x
			) {
			
			$ip = $1;
		}
	}	
	return $ip;
}
















__END__

=head1 NAME

AltiLog2Pcap.exe

=head1 DESCRIPTION

Convert SIP messages from MaxCS Trace Colleted logs to .pcap files.

=head1 SYNOPSIS

AltiLog2Pcap.exe [-i input_log_directory] [-o output_File] [-a ip_address]

AltiLog2Pcap.exe -h

=head1 USAGE

=over 4

=item B<-i>

B<input:> This should point to the \log directory of the extracted trace file.
If no value is provided, then the current directory will be used.

=item B<-o>

B<(output)> Name of the packet capture should be written.  If no value is provided, 
then the input directory will be used.

=item B<-a> 

B<(address)> The LAN IP address of the MaxCS server.  The SIP logs do not explicitly
contain this information. This program will attempt to pull the IP address out of the
configuration data in the trace collection. In the event that an argument is not passed,
and the program cannot find the IP address from the configuration data, then 10.100.100.100
will be used.

=back

=head1 WARNINGS & CAVEATS

This program will read the AltiGen logs from a collected trace package that contain SIP messages 
(SIPMan, SIPPstnReg, and SIPKeepALive files), grab the timestamp, network information about the 
message, and the messages themselves, and write them to a .pcap file that can then be analyzed by 
Wireshark.

It is important to understand that certain parts of this data are interpoloated, as the entirety 
of the network header is not provided in the log file.  If discrepancies arise between the output
of this file, and an actual capture of network traffic, the actual capture should be seen as authoritative.

Some of the shortcomings of this program:

=over 2

=item -

Ethernet addresses are strictly 22:22:22:11:11:11 for the MaxCS host and 22:22:22:22:22:22 for all
remote endpoints.  Sorry, this information isn't in the log files at all, so it's populated only to ensure
that the pcap format is valid.

=item -

The MaxCS server IP address is read in from the configuration data provided in the trace package.  Alternately,
it is possible to set this value on the commandline.  If it is not provided, and AltiLog2Pcap cannot find
the address from the config file, then 10.100.100.100 will be shown as the MaxCS address.

=item -

It's all UDP!  Even if the packet actually was TCP, we 'reconstitute' the packet as UDP in the packet capture.  The
logs do record the packet as having been TCP, so this is something that may change in the future.

=back

=cut
