package ATGN::PCAP::Util;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(hexdump);

use Modern::Perl;


sub hexdump {	
	my $in   = shift; 
	my $args = shift;
	my $hex  =  unpack "H* ", $in;
	my @nibs = ( $hex =~ m/../g );
	
	my $nib_count = scalar @nibs;
	my $counter_width =  length( sprintf("%x", $nib_count ) ) + 1;
	my $return;
	my $ascii = q{};	
	my $i    = 1;
	for my $nib (@nibs) {
		my $element = $nibs[$i - 1];
		if ( $i % 16 == 1 && $args->{rowcount} ) {
			$return .= sprintf("%0${counter_width}x:  %s ", $i - 1, $element, );
			$ascii  .= hex2ascii($element);
		}
		elsif ( $i % 8 == 0 ) {
			$return .= "$element    ";
			$ascii  .= hex2ascii($element) . q{ };
		}
		elsif ( $i % 4 == 0 ) {
			$return .= "$element  ";
			$ascii  .= hex2ascii($element);
		}
		else {
			$return .= "$element ";
			$ascii  .= hex2ascii($element);
		}
		
	

		if ( $i % 16 == 0 ) {
			$return .= "    $ascii" if $args->{ascii};
			$return .= "\n";
			$ascii = q{};
		}
		$i++;
	}
	
	return $return;
}

sub hex2ascii {
	my $num = hex(shift);
	return "." if $num < 31;
	return chr($num);
}