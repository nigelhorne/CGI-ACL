#!/usr/bin/env perl
# function.t -- white-box function-level tests for CGI::ACL

use strict;
use warnings;

use Test::Most;
use Test::Carp;
use Test::Memory::Cycle;
use Test::Mockingbird;
use Test::Returns;
use Readonly;
use Scalar::Util qw(refaddr);
use Socket qw(AF_INET);

# Load the module under test
BEGIN { use_ok('CGI::ACL') }

# ── Configuration ────────────────────────────────────────────────────────────

# All test constants live here; no magic strings or numbers elsewhere
Readonly my %config => (
	LOCAL_IP         => '127.0.0.1',
	RFC5737_IP       => '203.0.113.5',    # TEST-NET-3 per RFC 5737
	RFC5737_IP2      => '198.51.100.1',   # TEST-NET-2 per RFC 5737
	RFC5737_CIDR     => '192.0.2.0/24',   # TEST-NET-1 per RFC 5737
	CIDR_INSIDE      => '192.0.2.100',    # falls inside RFC5737_CIDR
	CIDR_OUTSIDE     => '10.0.0.1',       # outside all test CIDRs
	IPv6_ADDR        => '2001:db8::1',    # documentation IPv6 per RFC 3849
	IPv6_ADDR2       => '2001:db8::2',    # second documentation IPv6
	INVALID_IP       => 'not-an-ip',      # clearly malformed address
	INVALID_IP2      => '999.999.999.999',# out-of-range dotted quad
	COUNTRY_GB       => 'gb',
	COUNTRY_US       => 'us',
	COUNTRY_BR       => 'br',
	COUNTRY_GB_UPPER => 'GB',
	COUNTRY_US_UPPER => 'US',
	WILDCARD         => '*',
	AWS_HOST         => 'ec2-1-2-3-4.compute-1.amazonaws.com',
	GCP_HOST         => '203-0-113-5.bc.googleusercontent.com',
	AZURE_HOST       => 'myvm.cloudapp.net',
	DO_HOST          => 'myserver.digitalocean.something',
	NONCLOUD_HOST    => 'mail.example.com',
	DENY_ALL_WARN    => 'Usage: all_denied($lingua)',
	DENY_IP_WARN     => 'Usage: allow_ip($ip_address)',
	DENY_COUNTRY_WARN => 'Usage: deny_country($country)',
	ALLOW_COUNTRY_WARN => 'Usage: allow_country($country)',
	PLAIN_FN_WARN    => 'CGI::ACL: use ->new() not ::new() to instantiate',
);

# ── Mock Lingua helper ────────────────────────────────────────────────────────

# Minimal lingua stub that returns a fixed country code
{
	package Test::FakeLingua;
	sub new      { my ($class, $country) = @_; bless { country => $country }, $class }
	sub country  { $_[0]->{country} }
}

# ── Helper ───────────────────────────────────────────────────────────────────

# Run all_denied() with a controlled REMOTE_ADDR
sub denied_with_addr {
	my ($acl, $addr, @rest) = @_;
	local $ENV{REMOTE_ADDR} = $addr;
	return $acl->all_denied(@rest);
}

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: new()
# Purpose: verify constructor handles class method, function, and clone paths
# ─────────────────────────────────────────────────────────────────────────────
subtest 'new() - class method returns blessed CGI::ACL object' => sub {
	my $acl = CGI::ACL->new();

	# Must be a defined, blessed reference
	ok(defined $acl, 'new() returns defined value');
	isa_ok($acl, 'CGI::ACL', 'object has correct class');

	# Confirm schema compliance via Test::Returns
	returns_ok($acl, { type => 'OBJECT' }, 'return schema ok');

	# Fresh object has no restrictions
	is($acl->{allowed_ips},    undef, 'allowed_ips is undef initially');
	is($acl->{deny_countries}, undef, 'deny_countries is undef initially');
	is($acl->{allow_countries}, undef, 'allow_countries is undef initially');
	is($acl->{deny_cloud},     undef, 'deny_cloud is undef initially');
};

# Purpose: calling new() with pre-seeded hash populates the fields
subtest 'new() - with initial arguments' => sub {
	my $acl = CGI::ACL->new(deny_cloud => 1);

	isa_ok($acl, 'CGI::ACL', 'new with args returns object');
	is($acl->{deny_cloud}, 1, 'deny_cloud was pre-set via constructor');
};

# Purpose: calling on an existing object returns a shallow clone
subtest 'new() - shallow clone when called on an instance' => sub {
	my $orig = CGI::ACL->new(deny_cloud => 1);
	my $clone = $orig->new();

	isa_ok($clone, 'CGI::ACL', 'clone is a CGI::ACL object');
	isnt(refaddr($clone), refaddr($orig), 'clone is a different object');
	is($clone->{deny_cloud}, 1, 'clone inherits deny_cloud from original');
};

# Purpose: calling as a plain function (not a method) emits a carp warning
subtest 'new() - plain function call carps and returns undef' => sub {
	my $result;
	# CGI::ACL::new() with no args emits a carp (not croak)
	does_carp_that_matches(
		sub { $result = CGI::ACL::new() },
		qr/\Quse ->new() not ::new() to instantiate\E/,
	);
	is($result, undef, 'plain function call returns undef');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: allow_ip()
# Purpose: test IP storage, CIDR cache invalidation, error paths, and chaining
# ─────────────────────────────────────────────────────────────────────────────
subtest 'allow_ip() - positional scalar argument' => sub {
	my $acl = CGI::ACL->new();
	my $ret = $acl->allow_ip($config{RFC5737_IP});

	# The IP must appear in the allowed_ips hash
	ok($acl->{allowed_ips}{ $config{RFC5737_IP} }, 'IP stored in allowed_ips');

	# The method must return $self for chaining
	is($ret, $acl, 'returns $self');
	returns_ok($ret, { type => 'OBJECT' }, 'return schema ok');
};

# Purpose: named-parameter form stores IP correctly
subtest 'allow_ip() - named ip => argument' => sub {
	my $acl = CGI::ACL->new();
	$acl->allow_ip(ip => $config{RFC5737_IP});
	ok($acl->{allowed_ips}{ $config{RFC5737_IP} }, 'IP stored via named param');
};

# Purpose: hashref form stores IP correctly
subtest 'allow_ip() - hashref argument' => sub {
	my $acl = CGI::ACL->new();
	$acl->allow_ip({ ip => $config{RFC5737_IP} });
	ok($acl->{allowed_ips}{ $config{RFC5737_IP} }, 'IP stored via hashref');
};

# Purpose: adding an IP must delete the memoised _cidrlist cache
subtest 'allow_ip() - invalidates the _cidrlist cache' => sub {
	my $acl = CGI::ACL->new();

	# Seed a fake cache entry
	$acl->{_cidrlist} = ['dummy'];
	$acl->allow_ip($config{RFC5737_IP});

	# Cache must have been cleared
	ok(!defined $acl->{_cidrlist}, '_cidrlist deleted after allow_ip');
};

# Purpose: passing a non-hash reference emits a carp and returns $self
subtest 'allow_ip() - non-hash ref argument carps and chains' => sub {
	my $acl = CGI::ACL->new();
	my $ret;
	does_carp_that_matches(
		sub { $ret = $acl->allow_ip(\'bad scalar ref') },
		qr/\QUsage: allow_ip\E/,
	);
	is($ret, $acl, 'returns $self on bad-ref error path');
};

# Purpose: passing no ip key emits a carp and returns $self
subtest 'allow_ip() - missing ip key carps and chains' => sub {
	my $acl = CGI::ACL->new();
	my $ret;
	does_carp_that_matches(
		sub { $ret = $acl->allow_ip(notip => 'x') },
		qr/\QUsage: allow_ip\E/,
	);
	is($ret, $acl, 'returns $self on missing-key error path');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: deny_country()
# Purpose: test country storage, case folding, wildcard, arrayref, error paths
# ─────────────────────────────────────────────────────────────────────────────
subtest 'deny_country() - positional scalar stores lowercase' => sub {
	my $acl = CGI::ACL->new();
	my $ret = $acl->deny_country($config{COUNTRY_GB_UPPER});

	ok($acl->{deny_countries}{ $config{COUNTRY_GB} }, 'country stored lowercase');
	is($ret, $acl, 'returns $self');
	returns_ok($ret, { type => 'OBJECT' }, 'return schema ok');
};

# Purpose: named-parameter form stores country correctly
subtest 'deny_country() - named country => argument' => sub {
	my $acl = CGI::ACL->new();
	$acl->deny_country(country => $config{COUNTRY_US_UPPER});
	ok($acl->{deny_countries}{ $config{COUNTRY_US} }, 'country stored via named param');
};

# Purpose: hashref form stores country correctly
subtest 'deny_country() - hashref argument' => sub {
	my $acl = CGI::ACL->new();
	$acl->deny_country({ country => $config{COUNTRY_BR} });
	ok($acl->{deny_countries}{ $config{COUNTRY_BR} }, 'country stored via hashref');
};

# Purpose: arrayref stores all countries in the list
subtest 'deny_country() - arrayref of countries' => sub {
	my $acl = CGI::ACL->new();
	$acl->deny_country(country => [ $config{COUNTRY_GB_UPPER}, $config{COUNTRY_US_UPPER} ]);

	# Both must be present, lowercased
	ok($acl->{deny_countries}{ $config{COUNTRY_GB} }, 'first country stored');
	ok($acl->{deny_countries}{ $config{COUNTRY_US} }, 'second country stored');
};

# Purpose: wildcard '*' stored and triggers default-deny semantics
subtest 'deny_country() - wildcard' => sub {
	my $acl = CGI::ACL->new();
	$acl->deny_country($config{WILDCARD});
	ok($acl->{deny_countries}{ $config{WILDCARD} }, 'wildcard stored in deny_countries');
};

# Purpose: non-hash/non-array ref emits carp and returns $self
subtest 'deny_country() - bad ref carps and chains' => sub {
	my $acl = CGI::ACL->new();
	my $ret;
	does_carp_that_matches(
		sub { $ret = $acl->deny_country(\'not a hash or array ref') },
		qr/\QUsage: deny_country\E/,
	);
	is($ret, $acl, 'returns $self on bad-ref error path');
};

# Purpose: calling with no country key carps and returns $self
subtest 'deny_country() - missing key carps and chains' => sub {
	my $acl = CGI::ACL->new();
	my $ret;
	does_carp_that_matches(
		sub { $ret = $acl->deny_country() },
		qr/\QUsage: deny_country\E/,
	);
	is($ret, $acl, 'returns $self on missing argument');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: allow_country()
# Purpose: same interface as deny_country but writes to allow_countries
# ─────────────────────────────────────────────────────────────────────────────
subtest 'allow_country() - positional scalar stores lowercase' => sub {
	my $acl = CGI::ACL->new();
	my $ret = $acl->allow_country($config{COUNTRY_GB_UPPER});

	ok($acl->{allow_countries}{ $config{COUNTRY_GB} }, 'country stored lowercase');
	is($ret, $acl, 'returns $self');
	returns_ok($ret, { type => 'OBJECT' }, 'return schema ok');
};

# Purpose: arrayref of countries all stored in allow_countries
subtest 'allow_country() - arrayref of countries' => sub {
	my $acl = CGI::ACL->new();
	$acl->allow_country(country => [ $config{COUNTRY_GB_UPPER}, $config{COUNTRY_US_UPPER} ]);

	ok($acl->{allow_countries}{ $config{COUNTRY_GB} }, 'GB stored in allow_countries');
	ok($acl->{allow_countries}{ $config{COUNTRY_US} }, 'US stored in allow_countries');
};

# Purpose: bad-ref argument emits carp and still returns $self
subtest 'allow_country() - bad ref carps and chains' => sub {
	my $acl = CGI::ACL->new();
	my $ret;
	does_carp_that_matches(
		sub { $ret = $acl->allow_country(\42) },
		qr/\QUsage: allow_country\E/,
	);
	is($ret, $acl, 'returns $self on bad-ref error');
};

# Purpose: calling with no country key carps and returns $self
subtest 'allow_country() - missing key carps and chains' => sub {
	my $acl = CGI::ACL->new();
	my $ret;
	does_carp_that_matches(
		sub { $ret = $acl->allow_country() },
		qr/\QUsage: allow_country\E/,
	);
	is($ret, $acl, 'returns $self on missing argument');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: deny_cloud()
# Purpose: verify deny_cloud flag is set and method chaining works
# ─────────────────────────────────────────────────────────────────────────────
subtest 'deny_cloud() - sets flag and returns $self' => sub {
	my $acl = CGI::ACL->new();
	my $ret = $acl->deny_cloud();

	# Flag must be set to a true value
	ok($acl->{deny_cloud}, 'deny_cloud flag is set');
	is($ret, $acl, 'returns $self for chaining');
	returns_ok($ret, { type => 'OBJECT' }, 'return schema ok');
};

# Purpose: method chaining — deny_cloud followed by allow_ip must work
subtest 'deny_cloud() - full chain compiles without errors' => sub {
	my $acl = CGI::ACL->new()
		->deny_cloud()
		->allow_ip($config{RFC5737_IP});

	ok($acl->{deny_cloud},                          'deny_cloud set via chain');
	ok($acl->{allowed_ips}{ $config{RFC5737_IP} },  'IP set via chain');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: all_denied() — fast path (no restrictions)
# Purpose: no restrictions configured → always allow
# ─────────────────────────────────────────────────────────────────────────────
subtest 'all_denied() - no restrictions returns 0 (allow)' => sub {
	my $acl = CGI::ACL->new();
	local $ENV{REMOTE_ADDR} = $config{RFC5737_IP};

	my $result = $acl->all_denied();
	is($result, 0, 'allow when no restrictions are set');
	returns_ok($result, { type => 'SCALAR', regex => qr/^[01]$/ }, 'return schema ok');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: all_denied() — IP address validation
# Purpose: malformed REMOTE_ADDR always triggers a deny
# ─────────────────────────────────────────────────────────────────────────────
subtest 'all_denied() - invalid REMOTE_ADDR returns 1 (deny)' => sub {
	my $acl = CGI::ACL->new()->allow_ip($config{RFC5737_IP});

	# A non-IP string must be rejected even if allow_ip is configured
	local $ENV{REMOTE_ADDR} = $config{INVALID_IP};
	is($acl->all_denied(), 1, 'non-IP string in REMOTE_ADDR is denied');

	# An out-of-range dotted quad must also be rejected
	local $ENV{REMOTE_ADDR} = $config{INVALID_IP2};
	is($acl->all_denied(), 1, 'out-of-range IP is denied');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: all_denied() — IP allow-list
# Purpose: exact match and CIDR range matching
# ─────────────────────────────────────────────────────────────────────────────
subtest 'all_denied() - exact IP match allows access' => sub {
	my $acl = CGI::ACL->new()->allow_ip($config{RFC5737_IP});

	is(denied_with_addr($acl, $config{RFC5737_IP}),  0, 'allowed IP is not denied');
	is(denied_with_addr($acl, $config{RFC5737_IP2}), 1, 'unlisted IP is denied');
};

# Purpose: CIDR range lookups allow IPs inside the range
subtest 'all_denied() - CIDR range allows IPs inside the block' => sub {
	my $acl = CGI::ACL->new()->allow_ip($config{RFC5737_CIDR});

	is(denied_with_addr($acl, $config{CIDR_INSIDE}),  0, 'IP inside CIDR is allowed');
	is(denied_with_addr($acl, $config{CIDR_OUTSIDE}), 1, 'IP outside CIDR is denied');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: all_denied() — cloud blocking
# Purpose: deny_cloud blocks cloud IPs regardless of allow_ip entries
# ─────────────────────────────────────────────────────────────────────────────
subtest 'all_denied() - deny_cloud blocks cloud IPs (mocked)' => sub {
	# Mock _verified_rdns so the test never touches real DNS
	my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub {
		my $ip = $_[0];
		return $config{AWS_HOST}    if $ip eq $config{RFC5737_IP};
		return $config{NONCLOUD_HOST} if $ip eq $config{RFC5737_IP2};
		return undef;
	};

	# Both IPs are explicitly allowed; deny_cloud must still override for the cloud one
	my $acl = CGI::ACL->new()->deny_cloud()
		->allow_ip($config{RFC5737_IP})
		->allow_ip($config{RFC5737_IP2});

	# deny_cloud takes precedence over allow_ip
	is(denied_with_addr($acl, $config{RFC5737_IP}),  1, 'cloud IP denied even if allow_ip set');
	is(denied_with_addr($acl, $config{RFC5737_IP2}), 0, 'non-cloud IP is allowed');
};

# Purpose: deny_cloud alone (no other restrictions) denies cloud, allows others
subtest 'all_denied() - deny_cloud alone with cloud vs non-cloud' => sub {
	my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub {
		return $config{AWS_HOST} if $_[0] eq $config{RFC5737_IP};
		return undef;
	};

	my $acl = CGI::ACL->new()->deny_cloud();

	is(denied_with_addr($acl, $config{RFC5737_IP}),  1, 'cloud IP denied');
	is(denied_with_addr($acl, $config{RFC5737_IP2}), 0, 'non-cloud IP allowed');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: all_denied() — country restrictions
# Purpose: wildcard deny + allow list; specific deny list; no-lingua path
# ─────────────────────────────────────────────────────────────────────────────
subtest 'all_denied() - default-deny with allow list' => sub {
	my $acl = CGI::ACL->new()
		->deny_country($config{WILDCARD})
		->allow_country($config{COUNTRY_GB_UPPER});

	local $ENV{REMOTE_ADDR} = $config{LOCAL_IP};

	# Country in the allow list → access allowed
	my $allowed_lingua = Test::FakeLingua->new($config{COUNTRY_GB});
	is($acl->all_denied(lingua => $allowed_lingua), 0, 'allowed country is not denied');

	# Country NOT in the allow list → access denied
	my $denied_lingua = Test::FakeLingua->new($config{COUNTRY_BR});
	is($acl->all_denied(lingua => $denied_lingua), 1, 'non-allowed country is denied');
};

# Purpose: explicit deny list (not wildcard) denies named countries only
subtest 'all_denied() - explicit deny list' => sub {
	my $acl = CGI::ACL->new()->deny_country($config{COUNTRY_BR});

	local $ENV{REMOTE_ADDR} = $config{LOCAL_IP};

	# Country on the deny list → denied
	is($acl->all_denied(lingua => Test::FakeLingua->new($config{COUNTRY_BR})), 1, 'listed country is denied');

	# Country NOT on the deny list → allowed
	is($acl->all_denied(lingua => Test::FakeLingua->new($config{COUNTRY_GB})), 0, 'unlisted country is allowed');
};

# Purpose: unknown country (lingua returns undef) must always deny
subtest 'all_denied() - unknown country returns 1 (deny)' => sub {
	my $acl = CGI::ACL->new()->deny_country($config{COUNTRY_BR});

	local $ENV{REMOTE_ADDR} = $config{LOCAL_IP};
	is($acl->all_denied(lingua => Test::FakeLingua->new(undef)), 1, 'unknown country is denied');
};

# Purpose: country restrictions active but no lingua supplied must carp and deny
subtest 'all_denied() - no lingua with country restriction carps' => sub {
	my $acl = CGI::ACL->new()->deny_country($config{COUNTRY_BR});

	local $ENV{REMOTE_ADDR} = $config{LOCAL_IP};
	my $result;
	does_carp_that_matches(
		sub { $result = $acl->all_denied() },
		qr/\QUsage: all_denied\E/,
	);
	is($result, 1, 'returns 1 (deny) when no lingua is provided');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: all_denied() — CIDR cache memoisation
# Purpose: _cidrlist is built once and reused; invalidated by allow_ip
# ─────────────────────────────────────────────────────────────────────────────
subtest 'all_denied() - _cidrlist is memoised on first use' => sub {
	my $acl = CGI::ACL->new()->allow_ip($config{RFC5737_CIDR});

	# First call builds the cache
	ok(!defined $acl->{_cidrlist}, '_cidrlist absent before first call');
	denied_with_addr($acl, $config{CIDR_INSIDE});
	ok(defined $acl->{_cidrlist}, '_cidrlist populated after first call');

	# Second call reuses the cache (same reference)
	my $first_list = $acl->{_cidrlist};
	denied_with_addr($acl, $config{CIDR_INSIDE});
	is($acl->{_cidrlist}, $first_list, '_cidrlist reference is unchanged on reuse');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: _set_countries() (internal helper)
# Purpose: inserts lowercased codes; handles scalar and arrayref; no $_ clobber
# ─────────────────────────────────────────────────────────────────────────────
subtest '_set_countries() - scalar country stored lowercase' => sub {
	my $h = {};
	CGI::ACL::_set_countries($h, $config{COUNTRY_GB_UPPER});

	ok($h->{ $config{COUNTRY_GB} },        'uppercase input stored as lowercase');
	ok(!$h->{ $config{COUNTRY_GB_UPPER} }, 'original uppercase key is absent');
};

# Purpose: arrayref input stores every element, lowercased
subtest '_set_countries() - arrayref stores all codes lowercased' => sub {
	my $h = {};
	CGI::ACL::_set_countries($h, [ $config{COUNTRY_GB_UPPER}, $config{COUNTRY_US_UPPER} ]);

	ok($h->{ $config{COUNTRY_GB} }, 'GB stored from arrayref');
	ok($h->{ $config{COUNTRY_US} }, 'US stored from arrayref');
};

# Purpose: _set_countries must not clobber $_ in the calling scope
subtest '_set_countries() - does not clobber $_ in caller scope' => sub {
	my $h = {};

	# Set $_ to a sentinel and confirm it is unchanged after the call
	local $_ = 'sentinel-value';
	CGI::ACL::_set_countries($h, [ $config{COUNTRY_GB_UPPER}, $config{COUNTRY_US_UPPER} ]);
	is($_, 'sentinel-value', '$_ is unchanged after _set_countries with arrayref');

	# Repeat for scalar input
	local $_ = 'sentinel2';
	CGI::ACL::_set_countries($h, $config{COUNTRY_BR});
	is($_, 'sentinel2', '$_ is unchanged after _set_countries with scalar');
};

# Purpose: return value from _set_countries should be undef (void function)
subtest '_set_countries() - returns nothing (void context)' => sub {
	my $h = {};
	my @r = CGI::ACL::_set_countries($h, $config{COUNTRY_GB});
	is(scalar @r, 0, '_set_countries returns nothing in list context');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: _is_cloud_host() (internal helper)
# Purpose: returns 1 for cloud hostnames, 0 for non-cloud and undef PTR
# ─────────────────────────────────────────────────────────────────────────────
subtest '_is_cloud_host() - returns 1 for AWS hostname (mocked)' => sub {
	my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub { $config{AWS_HOST} };

	is(CGI::ACL::_is_cloud_host($config{RFC5737_IP}), 1, 'AWS hostname returns 1');
};

# Purpose: returns 1 for Google Cloud hostname
subtest '_is_cloud_host() - returns 1 for GCP hostname (mocked)' => sub {
	my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub { $config{GCP_HOST} };

	is(CGI::ACL::_is_cloud_host($config{RFC5737_IP}), 1, 'GCP hostname returns 1');
};

# Purpose: returns 1 for Azure hostname
subtest '_is_cloud_host() - returns 1 for Azure hostname (mocked)' => sub {
	my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub { $config{AZURE_HOST} };

	is(CGI::ACL::_is_cloud_host($config{RFC5737_IP}), 1, 'Azure hostname returns 1');
};

# Purpose: returns 1 for DigitalOcean hostname
subtest '_is_cloud_host() - returns 1 for DigitalOcean hostname (mocked)' => sub {
	my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub { $config{DO_HOST} };

	is(CGI::ACL::_is_cloud_host($config{RFC5737_IP}), 1, 'DigitalOcean hostname returns 1');
};

# Purpose: non-cloud hostname must return 0
subtest '_is_cloud_host() - returns 0 for non-cloud hostname (mocked)' => sub {
	my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub { $config{NONCLOUD_HOST} };

	is(CGI::ACL::_is_cloud_host($config{RFC5737_IP}), 0, 'residential hostname returns 0');
};

# Purpose: undef PTR (no record or verification failure) must return 0
subtest '_is_cloud_host() - returns 0 when _verified_rdns returns undef' => sub {
	my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub { undef };

	is(CGI::ACL::_is_cloud_host($config{RFC5737_IP}), 0, 'undef PTR returns 0');
};

# Purpose: IPv6 cloud IP is also blocked when its PTR matches a cloud pattern
subtest '_is_cloud_host() - returns 1 for IPv6 cloud hostname (mocked)' => sub {
	my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub { $config{AWS_HOST} };

	is(CGI::ACL::_is_cloud_host($config{IPv6_ADDR}), 1, 'IPv6 cloud host returns 1');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: _verified_rdns() (internal helper)
# Purpose: returns undef for invalid IPs; confirms forward lookup
# ─────────────────────────────────────────────────────────────────────────────
subtest '_verified_rdns() - invalid IPv4 string returns undef' => sub {
	# An obviously wrong string fails inet_aton, so the function returns undef
	my $result = CGI::ACL::_verified_rdns($config{INVALID_IP});
	is($result, undef, 'non-IP string returns undef');
};

# Purpose: out-of-range dotted quad also returns undef
subtest '_verified_rdns() - out-of-range IPv4 returns undef' => sub {
	my $result = CGI::ACL::_verified_rdns($config{INVALID_IP2});
	is($result, undef, 'out-of-range quad returns undef');
};

# Purpose: invalid IPv6 address fails inet_pton and returns undef
subtest '_verified_rdns() - invalid IPv6 string returns undef' => sub {
	my $result = CGI::ACL::_verified_rdns('not::a::valid::ipv6::too::many');
	is($result, undef, 'invalid IPv6 string returns undef');
};

# Purpose: when forward confirmation fails the function returns undef
subtest '_verified_rdns() - forward confirmation mismatch returns undef' => sub {
	# Mock _rdns_forward so the confirmed IP list does NOT include LOCAL_IP
	my $guard = mock_scoped 'CGI::ACL::_rdns_forward' => sub {
		return ('10.0.0.1');    # deliberately wrong IP in forward list
	};

	# Use 127.0.0.1: gethostbyaddr returns 'localhost' on this machine,
	# but the mocked forward confirms a different IP, so verification fails.
	my $result = CGI::ACL::_verified_rdns($config{LOCAL_IP});
	is($result, undef, 'mismatched forward confirmation returns undef');
};

# Purpose: when forward confirmation succeeds the hostname is returned
subtest '_verified_rdns() - successful forward confirmation returns hostname' => sub {
	# Mock _rdns_forward to confirm 127.0.0.1 so verification succeeds
	my $guard = mock_scoped 'CGI::ACL::_rdns_forward' => sub {
		return ($config{LOCAL_IP});
	};

	# 127.0.0.1 should have a PTR on any standard POSIX system
	my $result = CGI::ACL::_verified_rdns($config{LOCAL_IP});
	ok(defined $result, 'valid forward confirmation returns hostname (defined)');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: _rdns_forward() (internal helper)
# Purpose: IPv4 and IPv6 resolution paths
# ─────────────────────────────────────────────────────────────────────────────
subtest '_rdns_forward() - IPv4: resolves dotted quad back to itself' => sub {
	# inet_aton('127.0.0.1') => packed form; inet_ntoa => '127.0.0.1'
	my @ips = CGI::ACL::_rdns_forward($config{LOCAL_IP}, AF_INET);
	ok(grep { $_ eq $config{LOCAL_IP} } @ips, '127.0.0.1 resolves back to itself');
};

# Purpose: IPv4 with an unresolvable name returns an empty list
subtest '_rdns_forward() - IPv4: unresolvable hostname returns empty list' => sub {
	my @ips = CGI::ACL::_rdns_forward('this.hostname.does.not.exist.invalid', AF_INET);
	is(scalar @ips, 0, 'unresolvable hostname returns empty list');
};

# Purpose: IPv6 path uses getaddrinfo; mock it to return a controlled address
subtest '_rdns_forward() - IPv6: mocked getaddrinfo returns expected IPs' => sub {
	use Socket qw(NI_NUMERICHOST);

	# Build a fake sockaddr for getaddrinfo to return
	# Mock getaddrinfo to return one addr entry
	my $fake_sockaddr = pack('C4', 0, 0, 0, 0);    # dummy sockaddr
	my $guard_gai = mock_scoped 'Socket::getaddrinfo' => sub {
		return (0, { addr => $fake_sockaddr });
	};

	# Mock getnameinfo to return our expected IPv6 address
	my $guard_gni = mock_scoped 'Socket::getnameinfo' => sub {
		return (0, $config{IPv6_ADDR});
	};

	my $family = Socket::AF_INET6;
	my @ips = CGI::ACL::_rdns_forward('ip6-localhost', $family);
	ok(grep { $_ eq $config{IPv6_ADDR} } @ips, 'mocked IPv6 forward returns expected IP');
};

# Purpose: IPv6 path with getaddrinfo error returns empty list
subtest '_rdns_forward() - IPv6: getaddrinfo error returns empty list' => sub {
	my $guard = mock_scoped 'Socket::getaddrinfo' => sub {
		return ('Name or service not known');    # non-zero error string
	};

	my $family = Socket::AF_INET6;
	my @ips = CGI::ACL::_rdns_forward('nosuchhost.invalid', $family);
	is(scalar @ips, 0, 'getaddrinfo error returns empty list');
};

# ─────────────────────────────────────────────────────────────────────────────
# Subtest: memory cycle checks
# Purpose: objects must be garbage-collectible (no circular refs)
# ─────────────────────────────────────────────────────────────────────────────
subtest 'Memory cycle: plain ACL object has no cycles' => sub {
	my $acl = CGI::ACL->new();
	memory_cycle_ok($acl, 'fresh CGI::ACL object has no cycles');
};

# Purpose: an ACL with all restriction types set must also be cycle-free
subtest 'Memory cycle: fully configured ACL has no cycles' => sub {
	local $ENV{REMOTE_ADDR} = $config{LOCAL_IP};

	my $acl = CGI::ACL->new()
		->allow_ip($config{RFC5737_IP})
		->deny_country($config{COUNTRY_BR})
		->allow_country($config{COUNTRY_GB})
		->deny_cloud();

	# Trigger memoisation of _cidrlist by calling all_denied
	{
		my $guard = mock_scoped 'CGI::ACL::_verified_rdns' => sub { undef };
		$acl->all_denied(lingua => Test::FakeLingua->new($config{COUNTRY_GB}));
	}

	memory_cycle_ok($acl, 'fully configured ACL with cidrlist has no cycles');
};

done_testing();
