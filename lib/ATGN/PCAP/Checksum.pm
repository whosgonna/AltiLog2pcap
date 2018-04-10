package ATGN::PCAP::Checksum;

use Moo::Role;


sub calculate_checksum {
	my $packet = shift;
	
    my $bytes = length($packet);
    my $words = int($bytes / 2);
    my $chk = 0;
    my $count = $bytes;
	
	# Get the sum of all 16-bit words.
	for my $short (unpack("S$words", $packet)) {
        $chk += $short;
        $count = $count - 2;
    }
	
	# If there is a left over 8 bits (not sure if this is possible, given the previous
	# addition of a null byte if there is an odd number of bytes...
	if($count == 1) {
        $chk += unpack( "C", substr($packet, $bytes - 1, 1) );
    }
	
	# add the two halves together (CKSUM_CARRY -> libnet)
    $chk = ($chk >> 16) + ($chk & 0xffff);
    $chk = (~(($chk >> 16) + $chk) & 0xffff);
	
	return(unpack('n*', pack('S*', $chk)));
}


1;


__END__