package ATGN::PCAP::Data;

use Moo;
use Modern::Perl;


has 'data'   => ( is => 'ro', required => 1 );
has 'length' => ( is => 'lazy' );
has 'packed' => ( is => 'lazy' );


around BUILDARGS => sub {
	my $orig  = shift;
	my $class = shift;
	my %args  = @_;
	my $data = $args{data} // q{};
	
	#$data =~ s/\r?\n/\r\n/gims;
	return { data => $data };
	
};


sub _build_packed {
	my $self = shift;
	return pack("a*", $self->data);
}

sub _build_length {
	my $self = shift;
	my $length = length( $self->packed );
}



1;


__END__