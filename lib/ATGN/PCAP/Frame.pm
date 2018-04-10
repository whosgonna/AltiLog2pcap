package ATGN::PCAP::Frame;

use Moo;
use lib '../..';
use ATGN::PCAP::Data;
use ATGN::PCAP::UDP;
use ATGN::PCAP::IP;
use ATGN::PCAP::Ethernet;


# Maybe take a datetime argument here?
has 'ts_sec'       => ( is => 'ro', required => 1 ); # /* timestamp seconds */
has 'ts_usec'      => ( is => 'ro', required => 1 ); # /* timestamp microseconds */
has 'incl_len'     => ( is => 'lazy' );              #  /* number of octets of packet saved in file */
has 'orig_len'     => ( is => 'lazy' );              #  /* actual length of packet */
has 'frame_header' => ( is => 'lazy' );

# Items below might be good to create with defaults.
has 'l2_src'       => ( is => 'ro', required => 1 );
has 'l2_dst'       => ( is => 'ro', required => 1 );
has 'l3_proto'     => ( is => 'ro', default  => 0x0800 ); # IP
has 'l3_src'       => ( is => 'ro', required => 1 );
has 'l3_dst'       => ( is => 'ro', required => 1 );
has 'l4_proto'     => ( is => 'ro', default => 17 ); # UDP (yes, UDP)
has 'l4_src'       => ( is => 'ro', required => 1 );
has 'l4_dst'       => ( is => 'ro', required => 1 );
has 'data'         => ( is => 'ro', required => 1 );

has 'l2_obj'       => ( is => 'lazy' );
has 'l3_obj'       => ( is => 'lazy' );
has 'l4_obj'       => ( is => 'lazy' );

has 'headerless'   => ( is => 'lazy' );
has 'frame'        => ( is => 'lazy' );

around BUILDARGS => sub {
	# Using BUILDARGS to allow for some more user-friendly names when
	# passing the paramters 
	my $orig  = shift;
	my $class = shift;
	my %args  = @_;
	
	$args{l2_src}  //=  $args{ether_src};
	$args{l2_dst}  //=  $args{ether_dst};
	$args{l3_src}  //=  $args{src_host};
	$args{l3_dst}  //=  $args{dst_host};
	$args{l4_src}  //=  $args{src_port};
	$args{l4_dst}  //=  $args{dst_port};
	
	$args{data} = ATGN::PCAP::Data->new( data => $args{data} );
	
	return \%args;

};

sub _build_frame {
	my $self = shift;
	my $frame = $self->frame_header . $self->headerless;
	return $frame;
}


sub _build_headerless {
	my $self = shift;
	my $frame = 
		  $self->l2_obj->header
		. $self->l3_obj->header
		. $self->l4_obj->header
		. $self->data->packed
	;
		
}

sub _build_l2_obj {
	my $self = shift;
	
	my $l2_obj = ATGN::PCAP::Ethernet->new(
		ether_dst => $self->l2_dst,
		ether_src => $self->l2_src,
		#type      => 0x0800  ## IP is the default type.
	);
	
	return $l2_obj;
}



sub _build_l3_obj {
	my $self = shift;
	
	my $l3_obj = ATGN::PCAP::IP->new (
		src_host => $self->l3_src,
		dst_host => $self->l3_dst,
		l4_obj   => $self->l4_obj
	);
}



sub _build_l4_obj {
	my $self = shift;
	
	my $l4_obj = ATGN::PCAP::UDP->new(
		src_port => $self->l4_src,
		dst_port => $self->l4_dst,
		src_host => $self->l3_src,
		dst_host => $self->l3_dst,
		datagram => $self->data
	);
	
	
}

sub _build_incl_len {
	my $self = shift;
	return( length($self->headerless) );
}

sub _build_orig_len {
	my $self = shift;
	return $self->incl_len;
}

## libpcap header.
sub _build_frame_header {
	my $self = shift;
	my $header = #pack("LLLL", $tsec, $usec, $blen, $plen);
		pack( "L", $self->ts_sec   ) .
		pack( "L", $self->ts_usec  ) .
		pack( "L", $self->incl_len ) .
		pack( "L", $self->orig_len )
	;
}













1;


__END__