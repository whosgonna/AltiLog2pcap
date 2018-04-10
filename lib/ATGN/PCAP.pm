package ATGN::PCAP;
use Modern::Perl;

use Moo;
use lib '../';
use ATGN::PCAP::Frame;


has 'file'           => ( is => 'ro'   );
has '_fh'            => ( is => 'lazy' );
has 'libpcap_header' => ( is => 'lazy' );
has 'frame'          => ( is => 'ro', writer => '_set_frame'   );

## Only support ethernet for now?
has 'link_type'      => ( is => 'ro', default => 1 );  

sub BUILD {
	my $self = shift;	
	$self->_fh->print( $self->libpcap_header );
}

sub _build__fh {
	my $self = shift;
	my $file = $self->file;
	
	my $fh =  IO::File->new( $self->file, '>' ) ;
	$fh->binmode;
	
	return $fh;
}


sub _build_libpcap_header {
	my $self = shift;
	my $link_type = $self->link_type;

	my $header =  
		pack( "L", 0xa1b2c3d4 ) . 
		pack( "S", 2          ) . 
		pack( "S", 4          ) . 
		pack( "l", 0          ) . 
		pack( "L", 0          ) . 
		pack( "L", 65535      ) .
		pack( "L", $link_type )
	;
    
	return $header; 
}

sub dump {
	my $self = shift;
	#my $attr = shift;
	
	my $in   = shift; #$self->$attr;
	my $hex  =  unpack "H* ", $in;
	my @nibs = ( $hex =~ m/../g );
	my $i    = 1;
	for my $nib (@nibs) {
		my $element = $nibs[$i - 1];
		if ( $i % 16 == 0 ) {
			print "$element\n"
		}
		elsif ( $i % 8 == 0 ) {
			print "$element    ";
		}
		#elsif ( $i % 4 == 0 ) {
		#	print "$element   ";
		#}
		else {
			print "$element ";
		}	
		$i++;
	}
	print "\ndumped\n";
}


sub new_frame {
	my $self   = shift;
	my %args   = @_;
	my $frame = ATGN::PCAP::Frame->new(
		%args
	);
	
	$self->_fh->print($frame->frame);
	
	$self->_set_frame($frame);
}


1;

__END__