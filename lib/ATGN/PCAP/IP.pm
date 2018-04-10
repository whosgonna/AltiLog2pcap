package ATGN::PCAP::IP;

use Modern::Perl;
use Moo;

use lib '../..';
with 'ATGN::PCAP::Checksum';

has 'version'        => ( is => 'ro', default => 4  );
has 'header_len'     => ( is => 'rwp', default => 5 );
has 'diffserv'       => ( is => 'rwp', default => 0 );
has 'ecn'            => ( is => 'rwp', default => 0 );
has '_total_length'  => ( is => 'lazy', reader => 'total_length' );
has 'identification' => ( is => 'lazy' );
has 'flags'          => ( is => 'rwp', default => 0 );
has 'offset'         => ( is => 'rwp', default => 0 );
has 'ttl'            => ( is => 'rwp', default => 62 );
has 'protocol'       => ( is => 'ro',  default => 17 ); #Default UDP.
has 'checksum'       => ( is => 'rwp',default => 0, );
has 'src_host'       => ( is => 'ro', required => 1 );
has 'dst_host'       => ( is => 'ro', required => 1 );
has 'l4_obj'		 => ( is => 'ro', required => 1 );
has '_ver_and_len'   => ( is => 'lazy' );
has '_diff_and_ecn'  => ( is => 'lazy' );
has '_flag_offset'   => ( is => 'lazy' );

has 'header'         => ( is => 'lazy' );


sub _build_header {
	my $self = shift;
	
	if ( $self->checksum == 0 ) {
		my $header = $self->_craft_header;
		my $checksum = _build_checksum($header);
		$self->_set_checksum($checksum);
	}
	return $self->_craft_header;
}


sub _craft_header {
	my $self = shift;
	
	my $header = 
		  pack( 'B8',  $self->_ver_and_len )
		. pack( 'B8',  $self->_diff_and_ecn )
		. pack( 'n',   $self->total_length )
		. pack( 'n',   $self->identification )
		. pack( 'B16', $self->_flag_offset )
		. pack( 'C',   $self->ttl )
		. pack( 'C',   $self->protocol )
		. pack( 'n',   $self->checksum )
		. pack( 'C4',  split( '\.', $self->src_host ) )
		. pack( 'C4',  split( '\.', $self->dst_host ) )
	;
	
	return $header;
}





sub _build_checksum {
	my $header = shift;
	return calculate_checksum( $header );
};


sub _build__flag_offset {
	my $self = shift;
	return( sprintf( "%03b%013b", $self->flags, $self->offset ) );
}

sub _build__diff_and_ecn{
	my $self = shift;
	return( sprintf( "%06b%02b", $self->diffserv, $self->ecn ) );
}



sub _build__ver_and_len {
	my $self = shift;
	return( sprintf( "%04b%04b", $self->version, $self->header_len ) );
}
	

sub _build_identification {
	return 1885;
}

sub _build__total_length {
	my $self = shift;
	my $header_bytes = $self->header_len * 4; # header_len is wordcount
	return( $header_bytes + $self->l4_obj->length );
}


1;

__END__