package ATGN::PCAP::Ethernet;

use Modern::Perl;
use Moo;
use lib '../../';

has 'ether_dst' => ( is => 'ro', default => '0050569b2029' );
has 'ether_src' => ( is => 'ro', default => 'e8b7483261c3' );
has 'type'      => ( is => 'ro', default => 0x0800 );

has 'header'    => ( is => 'lazy' );

sub _build_header {
	my $self = shift;
	my $header = 
		  pack( 'H12', $self->ether_dst )
		. pack( 'H12', $self->ether_src )
		. pack( 'n',  $self->type )
	;
	
	return $header;
}



1;

__END__