#!perl -wT

use strict;
use warnings;
use Test::Most tests => 3;
use Test::NoWarnings;

BEGIN {
	use_ok('CGI::ACL');
}

IP: {
	my $acl = new_ok('CGI::ACL');

	$acl->allow_ip('212.58.246.78');
}
