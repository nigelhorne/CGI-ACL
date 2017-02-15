#!perl -wT

use strict;
use warnings;
use Test::Most tests => 10;
use Test::NoWarnings;

BEGIN {
	use_ok('CGI::ACL');
	use_ok('CGI::Lingua');
}

COUNTRY: {
	my $acl = new_ok('CGI::ACL');

	$acl->deny_country('br');
	$ENV{'REMOTE_ADDR'} = '131.161.10.233';	# Baidu

	my $lingua = new_ok('CGI::Lingua', [ supported => ['en'] ]);

	ok($acl->all_denied(lingua => $lingua));

	my @country_list = (
		'BY', 'MD', 'RU', 'CN', 'BR', 'UY', 'TR', 'MA', 'VE', 'SA', 'CY',
		'CO', 'MX', 'IN', 'RS', 'PK', 'UA'
	);
	$acl = new_ok('CGI::ACL')
		->deny_country(country => \@country_list);

	ok($acl->all_denied(lingua => $lingua));

	$acl->allow_ip('131.161.8.0/22');

	ok(!$acl->all_denied(lingua => $lingua));

	$ENV{'REMOTE_ADDR'} = '69.172.201.153';	# Google

	ok($acl->all_denied(lingua => $lingua));
}
