package ATGN::PCAP::UDP;

use Moo;
use Modern::Perl;
use lib '../../';
with 'ATGN::PCAP::Checksum';

has 'packed_header' => ( is => 'lazy' );
has 'src_port'      => ( is => 'ro', required => 1 );
has 'dst_port'		=> ( is => 'ro', required => 1 );
has 'length'        => ( is => 'lazy' );
has 'checksum'      => ( is => 'lazy' ); #checksum as a number - must be packed.

has '_pseudo_header' => ( is => 'lazy' );
has '_pseudo_packet' => ( is => 'lazy' );
# The L3 information is for creation of the pseudo header to calculate
# the checksum.
has 'src_host'      => ( is => 'ro', required => 1 );
has 'dst_host'      => ( is => 'ro', required => 1 );
has 'datagram'      => ( is => 'ro', required => 1 );

has 'header'        => ( is => 'lazy' );

my $protocol = 17; # UDP protocol number

sub _build_header {
	my $self = shift;
	
	my $header =
		  pack( "n", $self->src_port )
		. pack( "n", $self->dst_port )
		. pack( "n", $self->length   )
		. pack( "n", $self->checksum )
	;
}


sub _build_length {
	my $self   = shift;
	my $length = $self->datagram->length + 8;
	return $length;
}

sub _build__pseudo_header {
	my $self = shift;
 
    #my $src_ip = gethostbyname($ip->{src_ip});
    #my $dest_ip = gethostbyname($ip->{dest_ip});
 
    #no warnings;
 
    my $header; # = #pack 'a4 a4 C C n n n n n a*' =>
	$header	.= pack( 'C4', split( '\.', $self->src_host ) );
	$header	.= pack( 'C4', split( '\.', $self->dst_host ));
	$header	.= pack( 'C',  0 );
	$header	.= pack( 'C',  $protocol );
	$header	.= pack( 'n',  $self->length );
	$header	.= pack( 'n',  $self->src_port );
	$header	.= pack( 'n',  $self->dst_port );
	$header	.= pack( 'n',  $self->length );
	$header	.= pack( 'n',  0 );
	
	return $header;
}

sub _build__pseudo_packet {
	my $self = shift;
	my $packet = $self->_pseudo_header . $self->datagram->packed;
	if ( length($packet) % 2 ) {
	    $packet .= pack( 'n', 0 );
	}
		
	return $packet;
}

sub _build_checksum {
	my $self = shift;
	my $packet = $self->_pseudo_packet;
	return calculate_checksum($packet);	
}
	


1;


__END__