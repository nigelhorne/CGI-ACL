package CGI::ACL;

# Author Nigel Horne: njh@nigelhorne.com
# Copyright (C) 2017-2026, Nigel Horne
#
# Usage is subject to licence terms.


use 5.014;    # Socket::getaddrinfo/getnameinfo require Socket 2.000 (Perl 5.14)
use strict;
use warnings;
use autodie qw(:all);

# namespace::clean removes imported helper names from the public method list
use namespace::clean;

use Carp;
use Net::CIDR;
use Object::Configure;
use Params::Get;
use Readonly;
use Regexp::Common qw(net);
use Scalar::Util qw(blessed);
use Socket qw(AF_INET SOCK_STREAM inet_aton inet_ntoa);

# ── Compile-time constants ─────────────────────────────────────────────────────

# Maximum seconds to wait for a DNS reverse lookup on non-Windows platforms.
Readonly my $DNS_TIMEOUT  => 10;

# Seconds to cache a cloud-lookup result per IP in the per-object cache.
# Matches a typical short DNS TTL; balances freshness against resolver load.
Readonly my $CLOUD_CACHE_TTL => 300;

# Sentinel value stored in deny_countries to mean "deny every country".
Readonly my $WILDCARD     => q{*};

# Fallback client address when REMOTE_ADDR is absent (e.g. CLI or unit tests).
Readonly my $DEFAULT_ADDR => '127.0.0.1';

# Compiled regex for IP ranges that can never belong to a cloud provider:
# IPv4 loopback, RFC 1918 private blocks, link-local, and their IPv6 equivalents.
# Used by _is_cloud_host() to skip DNS entirely for these addresses.
Readonly my $PRIVATE_IP_RE => qr{
    ^(?:
        127\.                               | # IPv4 loopback (127.0.0.0/8)
        10\.                                | # RFC 1918 class A (10.0.0.0/8)
        192\.168\.                          | # RFC 1918 class C (192.168.0.0/16)
        172\.(?:1[6-9]|2[0-9]|3[01])\.     | # RFC 1918 class B (172.16.0.0/12)
        169\.254\.                            # IPv4 link-local (169.254.0.0/16)
    )
  | ^::1$                                     # IPv6 loopback
  | ^f[cd][0-9a-f]*:                          # IPv6 unique local (fc00::/7)
  | ^fe[89ab][0-9a-f]*:                       # IPv6 link-local (fe80::/10)
}xi;

# Compiled regexes that identify cloud-provider reverse-DNS hostnames.
# _is_cloud_host() iterates this list; to add a provider, append a qr// here.
Readonly my @CLOUD_PATTERNS => (
	qr/\.compute(?:-\d+)?\.amazonaws\.com$/i,   # AWS EC2
	qr/\.bc\.googleusercontent\.com$/i,          # Google Cloud Compute
	qr/\.cloudapp\.net$/i,                       # Microsoft Azure
	qr/\.azure\.com$/i,                          # Microsoft Azure (general)
	qr/digitalocean/i,                           # DigitalOcean
	qr/\.members\.linode\.com$/i,               # Linode / Akamai
	qr/hetzner/i,                               # Hetzner Cloud
	qr/your-server\.de$/i,                      # Hetzner (legacy dedicated)
	qr/\.ovh\.net$/i,                           # OVH Cloud
	qr/^ip-\d+-\d+-\d+-\d+\.eu$/i,             # OVH European IP range
);

# ── Version ────────────────────────────────────────────────────────────────────

=encoding utf-8

=head1 NAME

CGI::ACL - Decide whether to allow a client to run a CGI script

=head1 VERSION

Version 0.09

=cut

our $VERSION = '0.09';

=head1 SYNOPSIS

CGI::ACL controls who can run your CGI script.  You build a set of rules
and then call C<all_denied()> on every request.  If it returns C<1>,
send an error response or redirect; if it returns C<0>, allow the request.

Rules can be stacked in any order using method chaining.  An unrestricted
object (no rules added) allows everything.

=head2 Block all cloud-hosted visitors

The simplest use case -- no country list or lingua object needed.

    use CGI::ACL;

    my $acl = CGI::ACL->new()->deny_cloud();

    if ($acl->all_denied()) {
        print "Content-Type: text/plain\n\n";
        print "Automated cloud traffic is not permitted.\n";
        exit;
    }

=head2 Allow only specific IP addresses or CIDR ranges

Localhost is NOT automatically allowed once any restriction is set.
Add it explicitly if your script is called from the same machine.

    use CGI::ACL;

    my $acl = CGI::ACL->new()
        ->allow_ip('127.0.0.1')        # local machine
        ->allow_ip('203.0.113.0/24')   # office CIDR block
        ->allow_ip('2001:db8::1');     # single IPv6 address

    if ($acl->all_denied()) {
        print "Content-Type: text/plain\n\n";
        print "Your IP address is not on the allow list.\n";
        exit;
    }

=head2 Block visitors from specific countries

Deny mode: allow everyone except the listed countries.

    use CGI::Lingua;
    use CGI::ACL;

    my $lingua = CGI::Lingua->new(supported => ['en']);

    my $acl = CGI::ACL->new()
        ->deny_country('CN')
        ->deny_country(country => ['RU', 'KP']);

    if ($acl->all_denied(lingua => $lingua)) {
        print "Content-Type: text/plain\n\n";
        print "Access from your country is not permitted.\n";
        exit;
    }

=head2 Allow only specific countries (allowlist)

Default-deny mode: block everyone except the listed countries.
Use C<deny_all_countries()> to turn on default-deny, then list
each permitted country with C<allow_country()>.

    use CGI::Lingua;
    use CGI::ACL;

    my $lingua = CGI::Lingua->new(supported => ['en', 'de', 'fr']);

    my $acl = CGI::ACL->new()
        ->deny_all_countries()
        ->allow_country('GB')
        ->allow_country('US')
        ->allow_country('DE');

    if ($acl->all_denied(lingua => $lingua)) {
        print "Content-Type: text/plain\n\n";
        print "This service is available in GB, US, and DE only.\n";
        exit;
    }

=head2 Production-grade: IP allowlist + country allowlist + cloud block

Combine all three rule types.  Rules are evaluated in this fixed order:
cloud check, IP check, country check.

    use CGI::Lingua;
    use CGI::ACL;

    my $lingua = CGI::Lingua->new(supported => ['en']);

    my $acl = CGI::ACL->new()
        ->deny_cloud()                  # block AWS, GCP, Azure, etc.
        ->allow_ip('127.0.0.1')         # always allow localhost
        ->allow_ip('198.51.100.0/24')   # corporate network
        ->deny_all_countries()          # default-deny all countries...
        ->allow_country('GB')           # ...except UK
        ->allow_country('US');          # ...and US

    if ($acl->all_denied(lingua => $lingua)) {
        print "Content-Type: text/plain\n\n";
        print "Access denied.\n";
        exit;
    }

=head2 Sharing a base ACL across routes with cloning

Call C<new()> on an existing object to get an independent copy.
Changing the copy does not affect the original.

    use CGI::ACL;

    # Shared base: block cloud for all routes
    my $base_acl = CGI::ACL->new()->deny_cloud();

    # Admin route: additionally restrict to a single IP
    my $admin_acl = $base_acl->new()->allow_ip('198.51.100.1');

    if ($admin_acl->all_denied()) {
        print "Content-Type: text/plain\n\n";
        print "Admin access denied.\n";
        exit;
    }

The module optionally integrates with L<CGI::Lingua> for country detection.
Runtime configuration is supported via L<Object::Configure>.

=head1 COMMON PITFALLS

The following mistakes are easy to make.  Read this section before filing
a bug report.

=head2 allow_country alone has no effect

C<allow_country()> only restricts access when default-deny mode is active.
Default-deny mode is activated by C<deny_country('*')> or
C<deny_all_countries()>.  Without it, C<allow_country()> is silently
ignored and everyone is still allowed.

    # WRONG -- this allows everyone; allow_country is ignored
    my $acl = CGI::ACL->new()->allow_country('US');

    # RIGHT -- deny all countries first, then add permitted ones
    my $acl = CGI::ACL->new()->deny_all_countries()->allow_country('US');

=head2 deny_cloud overrides allow_ip

Cloud detection has the highest priority.  An IP address that is listed
in C<allow_ip()> is still blocked if its reverse DNS resolves to a cloud
provider hostname.  This is intentional: cloud IPs can be reassigned, so
the rDNS check is more reliable than the IP address alone.

    # This STILL blocks the IP if it is a cloud host
    my $acl = CGI::ACL->new()
        ->deny_cloud()
        ->allow_ip('198.51.100.5');   # blocked if rDNS says EC2

=head2 Localhost is not automatically allowed

Once any restriction is set, C<127.0.0.1> is subject to the same rules
as any other address.  If you need to allow local access (for example,
a health-check endpoint), add it explicitly.

    my $acl = CGI::ACL->new()
        ->allow_ip('127.0.0.1')   # must be explicit
        ->deny_all_countries()
        ->allow_country('US');

=head2 Forgetting the lingua argument

When country restrictions are active and C<all_denied()> is called without
a C<lingua> argument, the module emits a C<carp> warning and denies the
request.  Always pass a C<CGI::Lingua> object when country rules are in use.

    # WRONG -- will carp and deny every request
    my $acl = CGI::ACL->new()->deny_all_countries()->allow_country('US');
    $acl->all_denied();

    # RIGHT
    my $lingua = CGI::Lingua->new(supported => ['en']);
    $acl->all_denied(lingua => $lingua);

=head2 VPN and proxy users bypass IP and country checks

A visitor who connects through a VPN, Tor exit node, or anonymous proxy
will appear to come from the proxy's IP address and country, not their
own.  CGI::ACL has no way to detect this.  Cloud blocking provides some
mitigation for VPS-based proxies.

=head2 Country codes are case-insensitive but stored lowercase

C<deny_country('BR')> and C<deny_country('br')> are equivalent.  All
country codes are stored in lowercase.  C<CGI::Lingua::country()> may
return either case; C<all_denied()> normalises it with C<lc()> before
comparing.

=head2 The DNS result cache is not shared between CGI requests

In traditional CGI (one process per request), the per-object DNS cache
is destroyed at the end of every request.  The cache is only useful in
persistent-process setups such as FastCGI, mod_perl, or Plack servers,
where the same C<CGI::ACL> object survives across many requests.

=head1 SUBROUTINES/METHODS

=head2 new

Creates and returns a new CGI::ACL object.

When called on an existing object it returns a shallow clone of that object,
optionally overriding fields with the supplied arguments.

Constructor arguments may also be supplied via environment variables of the
form C<CGI__ACL__E<lt>fieldE<gt>> or via a config file; see L<Object::Configure>
for details.

=head3 EXAMPLE

    # No restrictions (allow all by default)
    my $acl = CGI::ACL->new();

    # Pre-seeded allow list
    my $acl = CGI::ACL->new(allowed_ips => { '127.0.0.1' => 1 });

    # Clone an existing ACL and add a restriction
    my $acl2 = $acl->new(deny_cloud => 1);

=head3 API SPECIFICATION

=head4 Input

    # Compatible with Params::Validate::Strict:
    {
        allowed_ips     => { type => 'hashref',  optional => 1 },
        deny_countries  => { type => 'hashref',  optional => 1 },
        allow_countries => { type => 'hashref',  optional => 1 },
        deny_cloud      => { type => 'boolean',  optional => 1 },
    }

=head4 Output

    # Compatible with Return::Set:
    { type => 'object', isa => 'CGI::ACL' }
    # or undef when called as CGI::ACL::new() instead of CGI::ACL->new()

=head3 MESSAGES

=over 4

=item C<< CGI::ACL use ->new() not ::new() to instantiate >>

B<Severity:> carp (warning).
B<Cause:> C<CGI::ACL::new(...)> was called as a plain function instead of
as a class method.
B<Action:> Change the call to C<< CGI::ACL->new(...) >>.

=back

=head3 FORMAL SPECIFICATION

    ──────────────── ACLState ────────────────────────────────────────
      allowed_ips    : IP_Str ⇸ Bool
      deny_countries : Country ⇸ Bool
      allow_countries: Country ⇸ Bool
      deny_cloud     : Bool
      _cidrlist      : [CIDR_Str]?   -- memoised; cleared on allow_ip
      _cloud_cache   : IP_Str ⇸ {result: Bool, expires: Nat}?
    ──────────────────────────────────────────────────────────────────

    ─────────────── New ──────────────────────────────────────────────
      class  : ClassName ∪ ACLState
      params : ACLState?
      ─────────────────────────────────────────────────────────────────
      blessed(class) ⟹
        result! = bless( class ∪ params, ref(class) )   -- clone
      ¬blessed(class) ⟹
        result! = bless( configure(class, params), class )
    ──────────────────────────────────────────────────────────────────

=cut

sub new {
	my $class = shift;

	# Parse arguments uniformly (hashref, named pairs, or no args)
	my $params = Params::Get::get_params(undef, @_);

	# Handle the rare case of being called as a plain function: CGI::ACL::new()
	if(!defined($class)) {
		Carp::carp(__PACKAGE__ . ': use ->new() not ::new() to instantiate');
		return;
	} elsif(blessed($class)) {
		# Called on an existing object: return a clone with deep-copied sub-hashes
		# so that mutations to the clone do not affect the original.
		$params //= {};
		my %copy = %{$class};
		for my $key (qw(allowed_ips deny_countries allow_countries)) {
			$copy{$key} = { %{$copy{$key}} } if ref($copy{$key}) eq 'HASH';
		}
		# Clear derived caches; they will be rebuilt fresh from the cloned state.
		delete $copy{_cidrlist};
		delete $copy{_cloud_cache};
		return bless { %copy, %{$params} }, ref($class);
	}

	# Merge any config-file or environment-variable overrides
	return bless Object::Configure::configure($class, $params), $class;
}

=head2 allow_ip

Adds an IPv4/IPv6 address or CIDR block to the set of explicitly permitted
clients.  When C<allowed_ips> is non-empty, any client address not matched
by an entry in the set is denied (subject to C<deny_cloud> taking precedence).

=head3 EXAMPLE

    use CGI::ACL;

    # Single address
    my $acl = CGI::ACL->new()->allow_ip('203.0.113.5');

    # Named parameter
    my $acl = CGI::ACL->new()->allow_ip(ip => '203.0.113.5');

    # CIDR block
    my $acl = CGI::ACL->new()->allow_ip(ip => '192.0.2.0/24');

    # Method chaining
    my $acl = CGI::ACL->new()
        ->allow_ip('192.0.2.1')
        ->allow_ip('10.0.0.0/8');

=head3 ARGUMENTS

=over 4

=item ip (required)

A string containing an IPv4 address, an IPv6 address, or a CIDR block
(e.g. C<10.0.0.0/8>).  The value is stored verbatim; invalid addresses
will be silently ignored during lookup.

=back

=head3 RETURNS

The object itself, to allow method chaining.

=head3 SIDE EFFECTS

Invalidates the internal CIDR lookup cache so the next call to
C<all_denied()> will rebuild it with the new entry included.

=head3 API SPECIFICATION

=head4 Input

    # Compatible with Params::Validate::Strict:
    {
        ip => { type => 'string', regex => qr/\S+/, required => 1 },
    }

=head4 Output

    # Compatible with Return::Set:
    { type => 'object', isa => 'CGI::ACL' }

=head3 MESSAGES

=over 4

=item C<Usage: allow_ip($ip_address)>

B<Severity:> carp (warning).
B<Cause:> Called with no argument, with a non-hash reference, or without
supplying the C<ip> key.
B<Action:> Pass a scalar IP/CIDR string: C<allow_ip('192.0.2.1')> or
C<allow_ip(ip =E<gt> '192.0.2.1')>.

=back

=head3 FORMAL SPECIFICATION

    ─────────────── AllowIP ──────────────────────────────────────────
      ΔACL
      ip? : IP_Str
      ─────────────────────────────────────────────────────────────────
      allowed_ips' = allowed_ips ∪ { ip? ↦ 1 }
      _cidrlist'   = ∅          -- cache invalidated
      deny_countries' = deny_countries
      allow_countries' = allow_countries
      deny_cloud'     = deny_cloud
    ──────────────────────────────────────────────────────────────────

=cut

sub allow_ip {
	my $self = shift;

	# Reject non-hash, non-scalar references (e.g. a scalar ref passed by mistake)
	if(ref($_[0]) && ref($_[0]) ne 'HASH') {
		Carp::carp('Usage: allow_ip($ip_address)');
		return $self;
	}

	# Extract the 'ip' parameter from positional, named, or hashref styles
	my $ip = _get_param('ip', @_);

	# Store the address and invalidate the memoised CIDR list
	if(defined $ip) {
		$self->{allowed_ips}->{$ip} = 1;
		delete $self->{_cidrlist};
	} else {
		Carp::carp('Usage: allow_ip($ip_address)');
	}
	return $self;
}

# ── deny_country ───────────────────────────────────────────────────────────────

=head2 deny_country

Adds one or more countries to the deny list.  Countries are identified by
their ISO 3166-1 alpha-2 codes (case-insensitive).

Passing the special value C<'*'> (wildcard) switches to default-deny mode:
all countries are denied unless they also appear in the allow list set by
C<allow_country()>.

=head3 EXAMPLE

    use CGI::ACL;

    # Deny a single country
    my $acl = CGI::ACL->new()->deny_country('BR');

    # Deny a list of countries
    my $acl = CGI::ACL->new()->deny_country(country => ['BR', 'CN', 'RU']);

    # Default-deny all countries (use with allow_country to whitelist)
    my $acl = CGI::ACL->new()->deny_country('*')->allow_country('US');

=head3 ARGUMENTS

=over 4

=item country (required)

A scalar ISO code, the wildcard C<'*'>, or an array reference of ISO codes.

=back

=head3 RETURNS

The object itself, to allow method chaining.

=head3 SIDE EFFECTS

Updates C<< $self->{deny_countries} >>.

=head3 NOTES

C<allow_country()> has no effect unless C<deny_country('*')> has been called
first.  Calling C<allow_country()> alone (without the wildcard deny) does
not restrict access.

=head3 API SPECIFICATION

=head4 Input

    # Compatible with Params::Validate::Strict:
    {
        country => {
            type     => 'string' | 'arrayref',
            required => 1,
        },
    }

=head4 Output

    # Compatible with Return::Set:
    { type => 'object', isa => 'CGI::ACL' }

=head3 MESSAGES

=over 4

=item C<Usage: deny_country($country)>

B<Severity:> carp (warning).
B<Cause:> Called with no argument, with a non-hash/non-array reference, or
without supplying the C<country> key.
B<Action:> Pass a scalar ISO code or arrayref:
C<deny_country('BR')> or C<deny_country(country =E<gt> ['BR','CN'])>.

=back

=head3 FORMAL SPECIFICATION

    ─────────────── DenyCountry ─────────────────────────────────────
      ΔACL
      country? : ISO_Code ∪ {'*'} ∪ seq ISO_Code
      ─────────────────────────────────────────────────────────────────
      country? ∈ seq ISO_Code ⟹
        deny_countries' = deny_countries ∪
                          { lc(c) ↦ 1 | c ∈ country? }
      country? ∉ seq ISO_Code ⟹
        deny_countries' = deny_countries ∪ { lc(country?) ↦ 1 }
      allow_countries' = allow_countries
      allowed_ips'     = allowed_ips
      deny_cloud'      = deny_cloud
    ──────────────────────────────────────────────────────────────────

=cut

sub deny_country {
	my $self = shift;

	# Reject references that are neither hashes nor arrays
	if(ref($_[0]) && ref($_[0]) ne 'HASH' && ref($_[0]) ne 'ARRAY') {
		Carp::carp('Usage: deny_country($country)');
		return $self;
	}

	# Extract the 'country' parameter from positional, named, or hashref styles
	my $c = _get_param('country', @_);

	# An empty arrayref is a no-op — do not create deny_countries = {}.
	if(defined $c) {
		return $self if ref($c) eq 'ARRAY' && !@{$c};
		_set_countries($self->{deny_countries} //= {}, $c);
	} else {
		Carp::carp('Usage: deny_country($country)');
	}
	return $self;
}

# ── allow_country ──────────────────────────────────────────────────────────────

=head2 allow_country

Adds one or more countries to the explicit permit list.  This is meaningful
only when C<deny_country('*')> has been called first; without the wildcard
deny, this method has no observable effect on access decisions.

=head3 EXAMPLE

    use CGI::ACL;

    # Allow only the UK and US
    my $acl = CGI::ACL->new()
        ->deny_country('*')
        ->allow_country(country => ['GB', 'US']);

    # Single country as positional argument
    my $acl = CGI::ACL->new()->deny_country('*')->allow_country('US');

=head3 ARGUMENTS

=over 4

=item country (required)

A scalar ISO code or an array reference of ISO codes.

=back

=head3 RETURNS

The object itself, to allow method chaining.

=head3 SIDE EFFECTS

Updates C<< $self->{allow_countries} >>.

=head3 NOTES

Call C<deny_country('*')> before this method; otherwise all traffic is
already allowed by the default-allow rule and the permit list is never
consulted.

=head3 API SPECIFICATION

=head4 Input

    # Compatible with Params::Validate::Strict:
    {
        country => {
            type     => 'string' | 'arrayref',
            required => 1,
        },
    }

=head4 Output

    # Compatible with Return::Set:
    { type => 'object', isa => 'CGI::ACL' }

=head3 MESSAGES

=over 4

=item C<Usage: allow_country($country)>

B<Severity:> carp (warning).
B<Cause:> Called with no argument, with a non-hash/non-array reference, or
without supplying the C<country> key.
B<Action:> Pass a scalar ISO code or arrayref:
C<allow_country('US')> or C<allow_country(country =E<gt> ['GB','US'])>.

=back

=head3 FORMAL SPECIFICATION

    ─────────────── AllowCountry ────────────────────────────────────
      ΔACL
      country? : ISO_Code ∪ seq ISO_Code
      ─────────────────────────────────────────────────────────────────
      country? ∈ seq ISO_Code ⟹
        allow_countries' = allow_countries ∪
                           { lc(c) ↦ 1 | c ∈ country? }
      country? ∉ seq ISO_Code ⟹
        allow_countries' = allow_countries ∪ { lc(country?) ↦ 1 }
      deny_countries' = deny_countries
      allowed_ips'    = allowed_ips
      deny_cloud'     = deny_cloud
    ──────────────────────────────────────────────────────────────────

=cut

sub allow_country {
	my $self = shift;

	# Reject references that are neither hashes nor arrays
	if(ref($_[0]) && ref($_[0]) ne 'HASH' && ref($_[0]) ne 'ARRAY') {
		Carp::carp('Usage: allow_country($country)');
		return $self;
	}

	# Extract the 'country' parameter from positional, named, or hashref styles
	my $c = _get_param('country', @_);

	# An empty arrayref is a no-op — do not create allow_countries = {}.
	if(defined $c) {
		return $self if ref($c) eq 'ARRAY' && !@{$c};
		_set_countries($self->{allow_countries} //= {}, $c);
	} else {
		Carp::carp('Usage: allow_country($country)');
	}
	return $self;
}

# ── deny_cloud ─────────────────────────────────────────────────────────────────

=head2 deny_cloud

Enables blocking of requests that originate from major cloud-hosting
providers.  Detection is performed via verified reverse DNS: the client
IP is looked up, the resulting hostname is forward-confirmed to prevent
spoofing, and the confirmed hostname is matched against a list of
provider-specific patterns.

Covered providers (as of this release): AWS EC2, Google Cloud Compute,
Microsoft Azure, DigitalOcean, Linode/Akamai, Hetzner, OVH.

B<Important:> C<deny_cloud> takes precedence over C<allow_ip>.  An IP
that is explicitly permitted via C<allow_ip()> is still denied if its
reverse DNS resolves to a cloud provider hostname.

=head3 EXAMPLE

    use CGI::ACL;

    my $acl = CGI::ACL->new()->deny_cloud();

    if ($acl->all_denied()) {
        print "Cloud-hosted clients are not permitted.\n";
        exit;
    }

=head3 ARGUMENTS

None.

=head3 RETURNS

The object itself, to allow method chaining.

=head3 SIDE EFFECTS

Sets C<< $self->{deny_cloud} >> to C<1>.

=head3 NOTES

IPv4 and IPv6 clients are both subject to the cloud check.  A client with
no reverse DNS record, or whose forward confirmation fails, is treated as
a non-cloud host and allowed through the cloud check (though it may still
be denied by other rules).

DNS lookups are performed synchronously.  On non-Windows platforms a
C<$DNS_TIMEOUT>-second alarm is used to prevent indefinite blocking.

=head3 API SPECIFICATION

=head4 Input

    # No parameters accepted.
    {}

=head4 Output

    # Compatible with Return::Set:
    { type => 'object', isa => 'CGI::ACL' }

=head3 MESSAGES

This method emits no messages.

=head3 FORMAL SPECIFICATION

    ─────────────── DenyCloud ───────────────────────────────────────
      ΔACL
      ─────────────────────────────────────────────────────────────────
      deny_cloud'     = 1
      allowed_ips'    = allowed_ips
      deny_countries' = deny_countries
      allow_countries'= allow_countries
      _cidrlist'      = _cidrlist
    ──────────────────────────────────────────────────────────────────

=cut

sub deny_cloud {
	my $self = shift;

	# Mark cloud-origin blocking as active
	$self->{deny_cloud} = 1;
	return $self;
}

# ── deny_all_countries ─────────────────────────────────────────────────────────

=head2 deny_all_countries

Convenience method equivalent to C<deny_country('*')>.  Switches the ACL
into default-deny mode for country checks: every country is denied unless
it also appears in the permit list added by C<allow_country()>.

This is the idiomatic way to build an allowlist-only country policy without
spelling out the wildcard literal.

=head3 EXAMPLE

    use CGI::ACL;

    # Allow only the UK and US; deny every other country
    my $acl = CGI::ACL->new()
        ->deny_all_countries()
        ->allow_country('GB')
        ->allow_country('US');

    if ($acl->all_denied(lingua => $lingua)) {
        print "Your country is not permitted.\n";
        exit;
    }

=head3 ARGUMENTS

None.

=head3 RETURNS

The object itself, to allow method chaining.

=head3 SIDE EFFECTS

Sets C<< $self->{deny_countries}{'*'} >> to C<1>, activating default-deny
mode.  C<allow_country()> calls made before or after this method both take
effect — evaluation order is irrelevant because all data is applied at
C<all_denied()> call time.

=head3 NOTES

C<allow_country()> has no restrictive effect unless this method (or
C<deny_country('*')>) has also been called.

=head3 API SPECIFICATION

=head4 Input

    # No parameters accepted.
    {}

=head4 Output

    # Compatible with Return::Set:
    { type => 'object', isa => 'CGI::ACL' }

=head3 MESSAGES

This method emits no messages.

=head3 FORMAL SPECIFICATION

    ─────────────── DenyAllCountries ────────────────────────────────
      ΔACL
      ─────────────────────────────────────────────────────────────────
      deny_countries' = deny_countries ∪ { '*' ↦ 1 }
      allow_countries' = allow_countries
      allowed_ips'    = allowed_ips
      deny_cloud'     = deny_cloud
    ──────────────────────────────────────────────────────────────────

=cut

sub deny_all_countries {
	my $self = shift;

	# Sugar for deny_country('*'): sets the wildcard sentinel that switches
	# all_denied() into default-deny mode for country checks.
	_set_countries($self->{deny_countries} //= {}, $WILDCARD);
	return $self;
}

# ── all_denied ─────────────────────────────────────────────────────────────────

=head2 all_denied

Evaluates every active restriction against the current client and returns
C<1> (deny) or C<0> (allow).

The evaluation order is:

=over 4

=item 1.

If B<no> restrictions are configured at all, return C<0> (allow).

=item 2.

Validate C<REMOTE_ADDR> as a syntactically correct IPv4 or IPv6 address.
If it is missing or malformed, return C<1> (deny).

=item 3.

If C<deny_cloud> is set, perform a verified reverse-DNS lookup.  If the
hostname matches a cloud provider, return C<1> (deny) immediately,
regardless of C<allowed_ips>.  If the IP is not a cloud host and no
other restrictions are active, return C<0> (allow).

=item 4.

If C<allowed_ips> is set, check the client address against the exact-match
hash and then the CIDR list.  Return C<0> (allow) on a match.

=item 5.

If country restrictions are set, resolve the client's country via the
C<lingua> argument.  Apply default-deny or default-allow country logic.
If no lingua is provided, emit a warning and return C<1> (deny).

=back

Note that localhost (C<127.0.0.1>) is B<not> automatically allowed once
any restriction is configured; call C<allow_ip('127.0.0.1')> explicitly.

=head3 EXAMPLE

    use CGI::Lingua;
    use CGI::ACL;

    my $acl = CGI::ACL->new()->allow_ip('8.35.80.39');

    if ($acl->all_denied()) {
        print "You are not allowed to view this site.\n";
        exit;
    }

    # Country check
    my $acl2 = CGI::ACL->new()
        ->deny_country('*')
        ->allow_country('US');

    if ($acl2->all_denied(lingua => CGI::Lingua->new(supported => ['en']))) {
        print "US-only site.\n";
        exit;
    }

=head3 ARGUMENTS

=over 4

=item lingua (optional)

A L<CGI::Lingua> object (or any object with a C<country()> method returning
an ISO 3166-1 alpha-2 code or C<undef>).  Required when country restrictions
are active; ignored otherwise.

=back

=head3 RETURNS

C<1> if access is denied, C<0> if access is allowed.

=head3 SIDE EFFECTS

May populate or update C<< $self->{_cidrlist} >> (the memoised CIDR lookup
structure) as a performance optimisation.

=head3 API SPECIFICATION

=head4 Input

    # Compatible with Params::Validate::Strict:
    {
        lingua => { type => 'object', optional => 1 },
    }

=head4 Output

    # Compatible with Return::Set:
    { type => 'string', regex => qr/^[01]$/ }

=head3 MESSAGES

=over 4

=item C<Usage: all_denied($lingua)>

B<Severity:> carp (warning).
B<Cause:> Country restrictions are active (C<deny_country> or
C<allow_country> was called) but no C<lingua> argument was supplied.
B<Action:> Pass a C<CGI::Lingua> object:
C<all_denied(lingua =E<gt> $lingua)>.

=back

=head3 PSEUDOCODE

    IF no restrictions configured THEN
        RETURN 0  (allow -- fast path)

    addr := REMOTE_ADDR // '127.0.0.1'
    IF addr not a valid IPv4 or IPv6 address THEN
        RETURN 1  (deny -- bad or injected address)

    IF deny_cloud is set THEN
        consult per-object cache keyed by addr (TTL 300 s)
        IF cache miss THEN
            is_cloud := _is_cloud_host(addr)  [DNS; may throw]
            IF no error THEN cache result END IF
        END IF
        IF is_cloud THEN RETURN 1 (deny -- cloud host)
        IF no other restrictions THEN RETURN 0 (allow)
    END IF

    IF allowed_ips is set THEN
        IF addr matches exact-match entry THEN RETURN 0 (allow)
        IF addr falls inside any CIDR range THEN RETURN 0 (allow)
    END IF

    IF deny_countries or allow_countries is set THEN
        IF no lingua supplied THEN carp; RETURN 1 (deny)
        IF lingua is not a blessed object THEN carp; RETURN 1 (deny)
        country := lingua->country()   [wrapped in eval]
        IF country is falsy (undef / "" / "0") THEN RETURN 1 (deny)
        country := lc(country)
        IF wildcard (*) in deny_countries THEN
            IF country in allow_countries THEN RETURN 0 (allow)
            ELSE                               RETURN 1 (deny)
        ELSE
            IF country in deny_countries THEN RETURN 1 (deny)
            ELSE                              RETURN 0 (allow)
        END IF
    END IF

    RETURN 1  (deny -- no rule permitted the request)

=head3 FORMAL SPECIFICATION

    ──────────────────────── AllDenied ──────────────────────────────
      ΞACL                          -- state unchanged (modulo cache)
      addr    : IPv4 ∪ IPv6         -- REMOTE_ADDR or DEFAULT_ADDR
      lingua? : Lingua              -- country resolver (optional)
      result! : {0, 1}              -- 0 = allow, 1 = deny
      ─────────────────────────────────────────────────────────────────
      no_restrictions(self) ⟹ result! = 0

      ¬valid_ip(addr) ⟹ result! = 1

      deny_cloud = 1 ∧ is_cloud(addr) ⟹ result! = 1
      deny_cloud = 1 ∧ ¬is_cloud(addr)
        ∧ allowed_ips = ∅ ∧ deny_countries = ∅
        ∧ allow_countries = ∅            ⟹ result! = 0

      addr ∈ dom(allowed_ips) ⟹ result! = 0
      cidr_match(addr, allowed_ips) ⟹ result! = 0

      (deny_countries ≠ ∅ ∨ allow_countries ≠ ∅)
        ∧ lingua? = ∅ ⟹ result! = 1
      lingua?.country() = undef ⟹ result! = 1

      deny_countries('*') = 1
        ∧ allow_countries(lc(lingua?.country())) = 1 ⟹ result! = 0
      deny_countries('*') = 1
        ∧ allow_countries(lc(lingua?.country())) ≠ 1 ⟹ result! = 1

      deny_countries('*') ≠ 1
        ∧ deny_countries(lc(lingua?.country())) = 1 ⟹ result! = 1
      deny_countries('*') ≠ 1
        ∧ deny_countries(lc(lingua?.country())) ≠ 1 ⟹ result! = 0
    ──────────────────────────────────────────────────────────────────

=cut

sub all_denied {
	my $self = shift;

	# Fast-path: if no restrictions are configured at all, allow immediately.
	# This guard must list every restriction type; missing one means that
	# restriction silently has no effect when used alone.
	if(
		(!defined($self->{allowed_ips}))    &&
		(!defined($self->{deny_countries})) &&
		(!$self->{deny_cloud})              &&
		(!defined($self->{allow_countries}))
	) {
		return 0;
	}

	# Determine the client address, falling back to localhost when absent.
	# Use // (defined-or) not || to avoid treating "0" or "" as absent.
	my $addr = $ENV{REMOTE_ADDR} // $DEFAULT_ADDR;

	# Reject addresses that are not syntactically valid IPv4 or IPv6
	return 1 unless $addr =~ /^$RE{net}{IPv4}$/o
	             || $addr =~ /^$RE{net}{IPv6}$/o;

	# ── Cloud check (highest precedence; overrides allow_ip) ────────────────
	if($self->{deny_cloud}) {
		# Consult the per-object cache before performing any DNS round-trips.
		# The cache stores {result, expires} keyed by IP address string.
		# This eliminates repeated DNS queries for the same IP within the TTL.
		my $cached = $self->{_cloud_cache} && $self->{_cloud_cache}{$addr};
		my ($is_cloud, $dns_error);
		if($cached && $cached->{expires} > time()) {
			$is_cloud = $cached->{result};
		} else {
			# Cache miss: perform the verified reverse-DNS lookup.
			# Wrap in eval: DNS failures must not kill the CGI process; fail safe.
			$is_cloud = eval { _is_cloud_host($addr) };
			$dns_error = $@;
			undef $@;   # we have captured the error; clear $@ so callers are not confused

			# Only cache definitive answers; errors are retried on the next request.
			unless($dns_error) {
				$self->{_cloud_cache}{$addr} = {
					result  => $is_cloud,
					expires => time() + $CLOUD_CACHE_TTL,
				};
			}
		}
		return 1 if !$dns_error && $is_cloud;

		# Non-cloud and no other restrictions: allow
		return 0 unless $self->{allowed_ips}
		             || $self->{deny_countries}
		             || $self->{allow_countries};
	}

	# ── IP / CIDR allow-list check ──────────────────────────────────────────
	if($self->{allowed_ips}) {
		# Check for an exact-match entry first (fast path)
		return 0 if $self->{allowed_ips}->{$addr};

		# Build and memoise the CIDR lookup structure on first use.
		# Wrap in eval: Net::CIDR dies on non-IP strings (injection attempts).
		if(!$self->{_cidrlist}) {
			my @cidrlist;
			for my $block (keys %{$self->{allowed_ips}}) {
				eval { @cidrlist = Net::CIDR::cidradd($block, @cidrlist) };
			}
			$self->{_cidrlist} = \@cidrlist;
		}

		# Check whether the address falls inside any allowed CIDR range.
		# Wrap in eval in case the list was built from partly-invalid entries.
		my $in_cidr = eval { Net::CIDR::cidrlookup($addr, @{$self->{_cidrlist}}) };
		return 0 if $in_cidr;
	}

	# ── Country check ───────────────────────────────────────────────────────
	if($self->{deny_countries} || $self->{allow_countries}) {
		# Extract lingua from positional, named, or hashref calling styles
		my $lingua = _get_param('lingua', @_);

		if($lingua) {
			# Reject non-objects to avoid "can't call method on non-ref" crashes
			unless(blessed($lingua)) {
				Carp::carp('all_denied: lingua must be a blessed object');
				return 1;
			}
			# Resolve and normalise the client's country code.
			# Wrap in eval: the object may not implement country().
			my $country_val = eval { $lingua->country() };
			if($@) { undef $@; return 1 }   # method missing or threw — deny
			if(my $country = $country_val) {
				$country = lc $country;

				# Default-deny mode: deny_countries contains the wildcard
				if($self->{deny_countries} && $self->{deny_countries}->{$WILDCARD}) {
					return ($self->{allow_countries} && $self->{allow_countries}->{$country})
						? 0   # country is explicitly permitted
						: 1;  # not in the permit list; deny
				}

				# Default-allow mode: deny only explicitly listed countries
				return ($self->{deny_countries} && $self->{deny_countries}->{$country})
					? 1   # country is explicitly denied
					: 0;  # not in the deny list; allow
			}
			# country() returned undef: country is unknown; deny access
		} else {
			# Country restrictions active but no lingua was provided
			Carp::carp('Usage: all_denied($lingua)');
		}
	}

	# Fall-through: no rule allowed the request; deny
	return 1;
}

# ── Internal helpers ──────────────────────────────────────────────────────────

# _set_countries
#
# Purpose:    Shared logic for deny_country() and allow_country().  Inserts one
#             or more lowercased country codes into the supplied hashref.
#
# Entry:      $hashref  - the target hash (already initialised by caller)
#             $value    - a scalar country code OR an arrayref of codes
#
# Exit:       Returns nothing (modifies $hashref in place).
#
# Side effects: Modifies the caller-supplied hashref.
#
# Notes:      Keys are forced to lower case for case-insensitive comparison.
sub _set_countries {
	my ($hashref, $value) = @_;

	# Handle both a single country code and a list reference.
	# Skip undef elements to avoid "uninitialised value" warnings.
	if(ref($value) eq 'ARRAY') {
		$hashref->{lc $_} = 1 for grep { defined } @{$value};
	} else {
		$hashref->{lc $value} = 1;
	}
	return;
}

# _get_param
#
# Purpose:    Normalise the three supported calling conventions — positional
#             scalar, named key-value pairs, and hashref — and extract one
#             named parameter from the caller's remaining @_ (after $self shift).
#             Bad-reference validation must be done by the caller BEFORE calling
#             this helper.
#
# Entry:      $key  - the parameter name to extract
#             @args - the method's remaining @_ after `my $self = shift`
#
# Exit:       Returns the value associated with $key, or undef if absent.
#             No side effects; does not modify @args or @_.
sub _get_param {
	my ($key, @args) = @_;
	return $args[0]{$key}     if ref($args[0]) eq 'HASH';
	return { @args }->{$key}  if @args % 2 == 0;
	return $args[0];          # positional: single value, no key
}

# _is_cloud_host
#
# Purpose:    Determines whether a given IP address belongs to a major cloud
#             provider by performing a verified reverse-DNS lookup and then
#             matching the confirmed hostname against @CLOUD_PATTERNS.
#
# Entry:      $ip - a validated IPv4 or IPv6 address string.
#
# Exit:       Returns 1 (cloud host) or 0 (not a cloud host / no PTR record).
#
# Side effects: Performs DNS lookups; may block for up to $DNS_TIMEOUT seconds
#               on non-Windows platforms.
#
# Notes:      An IP with no PTR record, or whose forward confirmation fails,
#             returns 0 (not cloud).  This is the safe default because
#             legitimate cloud providers consistently set rDNS records.
sub _is_cloud_host {
	my ($ip) = @_;

	# Private, loopback, and link-local addresses are never cloud provider IPs.
	# Skipping DNS for these eliminates the most common source of timeouts in
	# development environments and internal-network deployments.
	return 0 if $ip =~ $PRIVATE_IP_RE;

	# Attempt a verified reverse DNS lookup; returns undef on failure
	my $hostname = _verified_rdns($ip) or return 0;

	# Compare the confirmed hostname against every known cloud pattern
	for my $pattern (@CLOUD_PATTERNS) {
		return 1 if $hostname =~ $pattern;
	}
	return 0;
}

# _verified_rdns
#
# Purpose:    Performs a two-step DNS verification to prevent rDNS spoofing:
#               1. Reverse lookup: IP -> hostname
#               2. Forward confirmation: hostname -> [IPs]; IP must appear
#
# Entry:      $ip - a syntactically valid IPv4 or IPv6 address string.
#
# Exit:       Returns the confirmed hostname string on success, undef otherwise.
#             undef is returned when:
#               - $ip cannot be packed (invalid address)
#               - no PTR record exists
#               - forward lookup does not include the original IP
#               - DNS lookup times out (non-Windows only)
#
# Side effects: Performs two DNS round-trips; installs and restores a temporary
#               SIGALRM handler on non-Windows platforms.
#
# Notes:      On non-Windows platforms a $DNS_TIMEOUT-second alarm is set to
#             prevent CGI workers from blocking indefinitely on slow resolvers.
#             alarm(0) is called inside the eval to close the race window
#             between eval exit and the outer alarm(0) call.
sub _verified_rdns {
	my ($ip) = @_;

	# Determine address family and produce the packed binary address
	my ($family, $packed);
	if($ip =~ /:/) {
		# IPv6: use inet_pton which handles all valid IPv6 formats
		$family = Socket::AF_INET6;
		$packed = Socket::inet_pton(Socket::AF_INET6, $ip) or return;
	} else {
		# IPv4: inet_aton handles dotted-quad addresses
		$family = AF_INET;
		$packed = inet_aton($ip) or return;
	}

	# Normalise the IP to canonical form for reliable string comparison.
	# This handles abbreviated IPv6 forms such as '::1' vs '0:0:...:1'.
	my $canonical = ($family == AF_INET)
		? inet_ntoa($packed)
		: Socket::inet_ntop(Socket::AF_INET6, $packed);

	my ($hostname, @forward_ips);

	if($^O ne 'MSWin32') {
		# Non-Windows: guard against indefinitely-blocking DNS calls
		local $SIG{ALRM} = sub { die "DNS timeout: $ip" };
		my $old_alarm = alarm($DNS_TIMEOUT) // 0;
		eval {
			# Step 1: reverse lookup (IP -> hostname)
			$hostname = gethostbyaddr($packed, $family);
			if($hostname) {
				# Step 2: forward lookup (hostname -> IP list)
				@forward_ips = _rdns_forward($hostname, $family);
			}
			# Restore the previous alarm inside the eval to close the
			# race window between eval exit and the outer alarm() call.
			alarm($old_alarm);
		};
		# Belt-and-suspenders: restore the previous alarm whether eval threw or not
		alarm($old_alarm);
		return if $@ || !$hostname;
	} else {
		# Windows: no alarm support; perform lookups synchronously
		$hostname = gethostbyaddr($packed, $family) or return;

		# Forward lookup to confirm the hostname maps back to the original IP
		@forward_ips = _rdns_forward($hostname, $family);
	}

	# Step 3: the hostname is only trusted if a forward record confirms the IP
	return (grep { $_ eq $canonical } @forward_ips) ? $hostname : undef;
}

# _rdns_forward
#
# Purpose:    Resolves a hostname to a list of IP address strings for use in
#             the forward-confirmation step of _verified_rdns().
#
# Entry:      $hostname - the fully-qualified domain name to resolve.
#             $family   - address family: AF_INET or Socket::AF_INET6.
#
# Exit:       Returns a list of IP address strings (may be empty on failure).
#
# Side effects: Performs a DNS A or AAAA lookup.
#
# Notes:      For IPv4 uses the classic inet_aton/inet_ntoa chain.
#             For IPv6 uses Socket::getaddrinfo and Socket::getnameinfo
#             (available since Perl 5.14 / Socket 1.99).
sub _rdns_forward {
	my ($hostname, $family) = @_;

	# IPv4 path: resolve A record and convert each packed address to a string
	if($family == AF_INET) {
		return map  { inet_ntoa($_)  }
		       grep { defined        }
		       map  { inet_aton($_)  }
		       ($hostname);
	}

	# IPv6 path: use getaddrinfo to resolve AAAA records
	my ($err, @addrs) = Socket::getaddrinfo(
		$hostname, undef,
		{ family => $family, socktype => SOCK_STREAM },
	);
	return () if $err;

	# Convert each opaque sockaddr to a numeric IP string
	my @ips;
	for my $addr_info (@addrs) {
		my ($e, $host) = Socket::getnameinfo(
			$addr_info->{addr}, Socket::NI_NUMERICHOST,
		);
		push @ips, $host unless $e;
	}
	return @ips;
}

=head1 AUTHOR

Nigel Horne, C<< <njh at nigelhorne.com> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-cgi-acl at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=CGI-ACL>.

A VPN or proxy will most likely bypass IP-based access control.

=head1 SEE ALSO

=over 4

=item * L<CGI::Lingua>

=item * L<Configure an Object at Runtime|Object::Configure>

=item * L<Net::CIDR>

=item * L<Test Dashboard|https://nigelhorne.github.io/CGI-ACL/coverage/>

=back

=head1 SUPPORT

    perldoc CGI::ACL

=over 4

=item * MetaCPAN: L<https://metacpan.org/release/CGI-ACL>

=item * RT: L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=CGI-ACL>

=item * CPANTS: L<http://cpants.cpanauthors.org/dist/CGI-ACL>

=item * CPAN Testers: L<http://matrix.cpantesters.org/?dist=CGI-ACL>

=back


=head1 LIMITATIONS

=over 4

=item *

A VPN or anonymous proxy will likely bypass IP-based access control and may
defeat country detection as well.

=item *

Country detection relies on L<CGI::Lingua> and its underlying GeoIP database,
which must be updated regularly.  GeoIP databases are never fully accurate;
satellite and mobile networks in particular can be misattributed.

=item *

Cloud detection depends on provider-maintained reverse-DNS records.  A cloud
host whose PTR record does not follow its provider's naming convention will
not be detected.  Conversely, a legitimate host whose PTR record accidentally
matches a cloud pattern could be falsely denied.

=item *

DNS lookups are synchronous.  On non-Windows platforms a C<$DNS_TIMEOUT>-second
alarm prevents indefinite blocking, but under high resolver load that latency
can still affect every request for an uncached IP.  For persistent processes
(FastCGI, mod_perl) the built-in per-object cache (C<$CLOUD_CACHE_TTL> seconds)
mitigates this significantly.

=item *

The per-object DNS result cache is neither shared between processes nor
persistent across objects.  Under a pre-forking server each worker child
maintains an independent cache.

=item *

Private methods (C<_is_cloud_host>, C<_verified_rdns>, C<_rdns_forward>,
C<_set_countries>, C<_get_param>) are not enforced as private with
C<Sub::Private> because this module's white-box test suite (C<t/function.t>,
C<t/extended_tests.t>, etc.) calls them directly by fully-qualified name to
exercise specific code paths.  The C<namespace::clean> pragma removes them
from the object's method dispatch table, and the C<_> naming convention
signals their internal nature.

=item *

Windows platforms do not support C<alarm()>-based timeouts.  DNS lookups on
Windows block synchronously for as long as the OS resolver takes.

=item *

An optional rate-limiting feature (to block brute-force attacks) has not yet
been implemented.  It would require persistent shared state (e.g. Redis or an
in-memory cache) beyond this module's current dependency set.

=back

=head1 VERSION HISTORY

Notable changes per release.  See the F<Changes> file for the full list.

=head2 0.10 (development)

=over 4

=item *

Added C<deny_all_countries()>: a readable alternative to
C<deny_country('*')> for building country allowlists.

=item *

Factored out C<_get_param()>: a private helper that normalises the three
supported calling styles (positional scalar, named key-value pairs, hashref)
into one place.  Removes repeated dispatch code from C<allow_ip()>,
C<deny_country()>, C<allow_country()>, and C<all_denied()>.

=item *

Fixed minimum Perl version declaration: changed from C<use 5.006_001> to
C<use 5.014>.  C<Socket::getaddrinfo> and C<Socket::getnameinfo> require
Socket 2.000, which first shipped with Perl 5.14.  The declaration in
F<Makefile.PL> was corrected to match.

=item *

Fixed C<$@> not being cleared after catching errors from the DNS eval
block and from the C<lingua->country()> eval block.  A stale C<$@>
would confuse any outer eval in the caller.

=item *

Moved C<=encoding utf-8> to be the first POD directive in the file,
before C<=head1 NAME>.  This is required for the POD parser to correctly
handle the Z-calculus Unicode symbols used in the formal specifications.

=item *

Removed the vacuous C</o> modifier from the C<if ($ip =~ /:/)> pattern.
C</o> tells Perl to interpolate variables only once; it is a no-op on
patterns that contain no interpolated variables.

=item *

Replaced implicit C<use Socket> with an explicit import list to prevent
namespace pollution: C<use Socket qw(AF_INET SOCK_STREAM inet_aton inet_ntoa)>.

=item *

Corrected pragma order to the conventional C<use strict>, C<use warnings>,
C<use autodie> sequence.

=back

=head2 0.09

=over 4

=item *

Added private-IP short-circuit in C<_is_cloud_host()>: DNS is skipped
entirely for loopback (127.0.0.0/8, ::1), RFC 1918 private blocks
(10/8, 172.16/12, 192.168/16), and link-local addresses (169.254/16,
fe80::/10, fc00::/7).  These addresses can never be cloud provider IPs.

=item *

Added a per-object DNS result cache in C<all_denied()> with a 300-second
TTL.  Repeated requests from the same IP skip both DNS round-trips.
DNS errors are not cached; they are retried on the next request.

=back

=head2 0.08

=over 4

=item *

Fixed seven security and correctness bugs discovered in a full code review:
C<REMOTE_ADDR> defined-or fix, empty-arrayref no-op in country setters,
undef filter in C<_set_countries()>, Net::CIDR eval wrapping, non-blessed
lingua crash, missing C<country()> method crash, DNS exception propagation.

=item *

Fixed C<deny_cloud()> being bypassed when used without other restrictions.

=item *

Fixed IPv6 addresses bypassing cloud detection because C<inet_aton> is
IPv4-only.  C<_verified_rdns()> now uses C<Socket::inet_pton> for IPv6.

=item *

Fixed SIGALRM race: C<alarm(0)> is now called inside the eval block as
well as outside, closing the window where a late alarm could kill the
CGI process.

=item *

Added CIDR list cache in C<all_denied()> to avoid rebuilding the
C<Net::CIDR> list on every call.

=item *

Added 10-second DNS timeout on non-Windows platforms.

=back

=head2 0.07

=over 4

=item *

Added runtime configuration support via L<Object::Configure>.  Constructor
arguments can now be supplied as environment variables
(e.g., C<CGI__ACL__allowed_ips>) or from a config file.

=back

=head2 0.06

=over 4

=item *

Added C<deny_cloud()> to block requests from major cloud-hosting providers
using verified reverse DNS matching.

=item *

Added validation of C<REMOTE_ADDR> as a syntactically correct IP address.
Malformed or injected values are denied.

=back

=head2 0.05

=over 4

=item *

Calling C<new()> on an existing object now returns a clone of that object
instead of an empty default object.

=back

=head2 0.04

=over 4

=item *

Access is now denied when the visitor's country cannot be determined,
rather than defaulting to allow.  Localhost (127.0.0.1) is no longer
automatically permitted once any restriction is configured.

=back

=head2 0.03

=over 4

=item *

Added C<allow_country()> and support for C<deny_country('*')>
(default-deny mode for countries).

=back

=head2 0.01 -- 0.02

Initial release.  Basic IP allowlist and country deny-list support.

=head1 LICENSE AND COPYRIGHT

Copyright 2017-2026 Nigel Horne.

Usage is subject to the GPL2 licence terms.
If you use it,
please let me know.

=cut

1;
