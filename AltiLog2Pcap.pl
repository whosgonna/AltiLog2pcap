use Modern::Perl;

use IO::File;
use IO::All;
use lib './lib/';
use ATGN::PCAP;
use ATGN::PCAP::Util qw(hexdump);
use Time::Local;

my $dirname   = $ARGV[0] // '.';



my $cap = ATGN::PCAP->new({file => "$dirname/SIPLogs.pcap"});

my $host_ip     = get_ip($dirname) // '5.4.3.2';
my $ether_local = '222222111111';
my $ether_rmt   = '222222222222';
my $loglines;


use Data::Printer;

my $dir = io($dirname);
my $files =  [ $dir->all_files ];


for my $file ( @$files ) {
	next unless ( $file->filename =~ /( ^SIPMan.*\.txt$ | ^SIPPstnReg.*txt$ | ^SIPKeepALive.*txt$ )/x );


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
			$line->{month},
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

