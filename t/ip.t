#!perl -wT

use strict;
use warnings;
use Test::Most tests => 10;
use Test::NoWarnings;

BEGIN {
	use_ok('CGI::ACL');
	use_ok('CGI::Info');
}

IP: {
	my $acl = new_ok('CGI::ACL');

	$acl->allow_ip('212.58.246.78');

	my $info = new_ok('CGI::Info');

	$ENV{'REMOTE_ADDR'} = '212.58.246.78';
	ok(!$acl->all_denied(info => $info));

	$ENV{'REMOTE_ADDR'} = '8.35.80.39';
	ok($acl->all_denied(info => $info));

	$acl = new_ok('CGI::ACL');

	$acl->allow_ip('8.0.0.0/8');
	ok(!$acl->all_denied(info => $info));

	$ENV{'REMOTE_ADDR'} = '212.58.246.78';
	ok($acl->all_denied(info => $info));
}
