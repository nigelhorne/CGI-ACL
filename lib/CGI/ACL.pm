package CGI::ACL;

# Author Nigel Horne: njh@bandsman.co.uk
# Copyright (C) 2017, Nigel Horne

# Usage is subject to licence terms.
# The licence terms of this software are as follows:
# Personal single user, single computer use: GPL2
# All other users (including Commercial, Charity, Educational, Government)
#	must apply in writing for a licence for use from Nigel Horne at the
#	above e-mail.

use 5.006_001;
use warnings;
use strict;
use namespace::clean;
use Carp;

=head1 NAME

CGI::ACL - Decide whether to allow a client to run this script

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Does what it says on the tin.

    use CGI::Info;
    use CGI::ACL;

    my $acl = CGI::ACL->new();
    # ...
    my $allowed = $acl->allow(info => CGI::Info->new());

=head1 SUBROUTINES/METHODS

=head2 new

Creates a CGI::ACL object.

Takes a parameter which is tells you about the environment you're running in, e.g.
an L<CGI::Info> object.

=cut

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;

	return unless(defined($class));

	my %args = (ref($_[0]) eq 'HASH') ? %{$_[0]} : @_;

	return bless { }, $class;
}

=head2 allow_ip

Give an IP (or CIDR) that we allow to connect to us

    use CGI::Info;
    use CGI::ACL;

    # Allow Google to connect to us
    my $acl = CGI::ACL->new(info => CGI::Info->new())->allow_ip(ip => '8.35.80.39');

=cut

sub allow_ip {
	my $self = shift;
	my %params;
	
	if(ref($_[0]) eq 'HASH') {
		%params = %{$_[0]};
	} elsif(@_ % 2 == 0) {
		%params = @_;
	} else {
		$params{'ip'} = shift;
	}

	if(!defined($params{'ip'})) {
		Carp::carp 'Usage: allow_ips($ip_address)';
	} else {
		$self->{_allowed_ips}->{$params{'ip'}} = 1;
	}
}

=head1 AUTHOR

Nigel Horne, C<< <njh at bandsman.co.uk> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-cgi-acl at rt.cpan.org>,
or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=CGI-ACL>.
I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SEE ALSO

L<CGI::Info>

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc CGI::ACL

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=CGI-ACL>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/CGI-ACL>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/CGI-ACL>

=item * Search CPAN

L<http://search.cpan.org/dist/CGI-ACL/>

=back

=head1 LICENSE AND COPYRIGHT

Copyright 2017 Nigel Horne.

This program is released under the following licence: GPL

=cut

1; # End of CGI::ACL
