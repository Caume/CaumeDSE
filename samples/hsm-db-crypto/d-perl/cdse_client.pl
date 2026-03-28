#!/usr/bin/perl
###############################################################################
# cdse_client.pl - Caume Data Security Engine (CaumeDSE) REST API client
#
# Copyright 2010-2026 by Omar Alejandro Herrera Reyna
#
#   CaumeDSE is free software: you can redistribute it and/or modify it under
#   the terms of the GNU General Public License (v3 or later).
#   See <http://www.gnu.org/licenses/> for details.
#
# SYNOPSIS
#   cdse_client.pl [OPTIONS] COMMAND [ARGS...]
#
# DESCRIPTION
#   Sample client simulating an HSM + encrypted database + general crypto
#   interface via the CaumeDSE HTTPS REST API.
#
# OPTIONS
#   --server HOST:PORT   CaumeDSE server (default: localhost:8443)
#   --userId  ID         User ID (or env CDSE_USER_ID)
#   --orgId   ID         Organization ID (or env CDSE_ORG_ID)
#   --orgKey  KEY        Organization encryption key (or env CDSE_ORG_KEY)
#   --storage NAME       Storage name (default: EngineStorage or CDSE_STORAGE)
#   --insecure           Disable TLS certificate verification
#   --ca-cert FILE       PEM CA certificate file for TLS verification
#   --interactive / -i   Interactive prompt mode (prompts for credentials)
#
# COMMANDS
#   info                            Show user/org info
#   list-secrets                    List stored raw file secrets
#   store-secret NAME FILE [INFO]   Upload FILE as encrypted secret NAME
#   get-secret NAME [OUTFILE]       Retrieve secret (print or write to OUTFILE)
#   delete-secret NAME              Delete a secret
#   db-list                         List CSV databases
#   db-create NAME col1,col2,...    Create a new CSV database
#   db-insert NAME col=val ...      Append a row to CSV database
#   db-query NAME [ROW]             Query all rows or a specific row number
#   db-update NAME ROW col=val ...  Update row ROW in CSV database
#   db-delete-row NAME ROW          Delete row ROW from CSV database
#   db-delete NAME                  Delete entire CSV database
#   audit-log                       Show transaction audit log
#   help                            Show this help
#
# EXAMPLES
#   # One-shot mode using env vars:
#   export CDSE_USER_ID=admin CDSE_ORG_ID=MyOrg CDSE_ORG_KEY=s3cr3t
#   export CDSE_SERVER=myserver:8443 CDSE_STORAGE=EngineStorage
#   cdse_client.pl --ca-cert /etc/cdse/ca.pem info
#   cdse_client.pl store-secret mykey /tmp/keyfile.bin "My AES key"
#   cdse_client.pl get-secret mykey /tmp/keyfile-out.bin
#   cdse_client.pl db-create payroll "name,salary,dept"
#   cdse_client.pl db-insert payroll name=Alice salary=90000 dept=Engineering
#   cdse_client.pl db-query payroll
#   cdse_client.pl db-update payroll 1 salary=95000
#   cdse_client.pl db-delete-row payroll 1
#   cdse_client.pl audit-log
#
#   # Interactive mode:
#   cdse_client.pl --interactive --server myserver:8443 --ca-cert /etc/cdse/ca.pem
#
###############################################################################
use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case bundling);
use File::Basename;
use LWP::UserAgent;
use HTTP::Request::Common;
use URI::Escape;

###############################################################################
# Optional: Term::ReadKey for hidden password entry
###############################################################################
my $have_readkey = 0;
eval {
    require Term::ReadKey;
    Term::ReadKey->import();
    $have_readkey = 1;
};

###############################################################################
# Global configuration
###############################################################################
my %cfg = (
    server      => $ENV{CDSE_SERVER}   || 'localhost:8443',
    userId      => $ENV{CDSE_USER_ID}  || '',
    orgId       => $ENV{CDSE_ORG_ID}   || '',
    orgKey      => $ENV{CDSE_ORG_KEY}  || '',
    storage     => $ENV{CDSE_STORAGE}  || 'EngineStorage',
    insecure    => 0,
    ca_cert     => '',
    interactive => 0,
);

###############################################################################
# Parse command-line options
###############################################################################
GetOptions(
    'server=s'      => \$cfg{server},
    'userId=s'      => \$cfg{userId},
    'orgId=s'       => \$cfg{orgId},
    'orgKey=s'      => \$cfg{orgKey},
    'storage=s'     => \$cfg{storage},
    'insecure'      => \$cfg{insecure},
    'ca-cert=s'     => \$cfg{ca_cert},
    'interactive|i' => \$cfg{interactive},
) or die "Error parsing options. Run '$0 help' for usage.\n";

###############################################################################
# Build LWP::UserAgent with appropriate TLS settings
###############################################################################
sub make_ua {
    my %ssl_opts = ( verify_hostname => 1 );
    if ($cfg{insecure}) {
        $ssl_opts{verify_hostname} = 0;
        $ssl_opts{SSL_verify_mode} = 0;
    }
    elsif ($cfg{ca_cert}) {
        $ssl_opts{SSL_ca_file} = $cfg{ca_cert};
    }
    return LWP::UserAgent->new(
        ssl_opts => \%ssl_opts,
        timeout  => 60,
    );
}

###############################################################################
# Helpers: URL building and request execution
###############################################################################

# Base URL for the API.  If $cfg{server} already contains a scheme
# ("http://" or "https://") it is used as-is; otherwise "https://" is prepended.
sub base_url {
    return $cfg{server} if $cfg{server} =~ m{^https?://};
    return "https://$cfg{server}";
}

# Auth query parameters (always required)
sub auth_params {
    return (
        userId => $cfg{userId},
        orgId  => $cfg{orgId},
        orgKey => $cfg{orgKey},
    );
}

# Append a hash of params as a query string to a URL
sub append_query {
    my ($url, %params) = @_;
    my @pairs;
    for my $k (sort keys %params) {
        push @pairs, uri_escape($k) . '=' . uri_escape($params{$k});
    }
    return $url . '?' . join('&', @pairs);
}

# Execute a prepared HTTP::Response and print result or die on error
sub do_request {
    my ($ua, $req) = @_;
    my $res = $ua->request($req);
    unless ($res->is_success) {
        warn "HTTP error: " . $res->status_line . "\n";
        warn $res->decoded_content . "\n" if $res->decoded_content;
        return undef;
    }
    return $res->decoded_content;
}

# Simple GET request
sub do_get {
    my ($ua, $path, %extra_params) = @_;
    my %params = (auth_params(), %extra_params);
    my $url = append_query(base_url() . $path, %params);
    my $req = HTTP::Request->new(GET => $url);
    return do_request($ua, $req);
}

# Simple DELETE request
sub do_delete {
    my ($ua, $path, %extra_params) = @_;
    my %params = (auth_params(), %extra_params);
    my $url = append_query(base_url() . $path, %params);
    my $req = HTTP::Request->new(DELETE => $url);
    return do_request($ua, $req);
}

# PUT request with all params in query string
sub do_put {
    my ($ua, $path, %extra_params) = @_;
    my %params = (auth_params(), %extra_params);
    my $url = append_query(base_url() . $path, %params);
    my $req = HTTP::Request->new(PUT => $url);
    return do_request($ua, $req);
}

# POST request for contentRows (params in query string, no body)
sub do_post_params {
    my ($ua, $path, %extra_params) = @_;
    my %params = (auth_params(), %extra_params);
    my $url = append_query(base_url() . $path, %params);
    my $req = HTTP::Request->new(POST => $url);
    return do_request($ua, $req);
}

# Multipart POST for file upload
sub do_post_multipart {
    my ($ua, $path, $file_path, $resource_info, %extra_params) = @_;
    my $url = base_url() . $path;
    my @content = (
        file             => [$file_path],
        userId           => $cfg{userId},
        orgId            => $cfg{orgId},
        orgKey           => $cfg{orgKey},
        '*resourceInfo'  => (defined $resource_info ? $resource_info : ''),
    );
    for my $k (sort keys %extra_params) {
        push @content, $k, $extra_params{$k};
    }
    my $req = POST($url,
        Content_Type => 'form-data',
        Content      => \@content,
    );
    return do_request($ua, $req);
}

# Multipart POST for CSV DB creation (upload a CSV header string as a file)
sub do_post_csv_create {
    my ($ua, $path, $csv_header) = @_;
    my $url = base_url() . $path;

    # Build a temporary in-memory "file" from the CSV header line
    require HTTP::Request::Common;
    my @content = (
        file             => [undef, 'schema.csv',
                             'Content-Type'        => 'text/csv',
                             'Content-Disposition' => 'form-data; name="file"; filename="schema.csv"',
                             Content => $csv_header],
        userId           => $cfg{userId},
        orgId            => $cfg{orgId},
        orgKey           => $cfg{orgKey},
        '*resourceInfo'  => '',
    );
    my $req = POST($url,
        Content_Type => 'form-data',
        Content      => \@content,
    );
    return do_request($ua, $req);
}

###############################################################################
# Credential prompting (interactive mode)
###############################################################################
sub prompt_credentials {
    print "CaumeDSE Interactive Client\n";
    print "============================\n";

    print "Server [localhost:8443]: ";
    chomp(my $srv = <STDIN>);
    $cfg{server} = $srv if $srv;

    print "Storage [EngineStorage]: ";
    chomp(my $st = <STDIN>);
    $cfg{storage} = $st if $st;

    print "User ID: ";
    chomp($cfg{userId} = <STDIN>);

    print "Org ID: ";
    chomp($cfg{orgId} = <STDIN>);

    if ($have_readkey) {
        print "Org Key (hidden): ";
        Term::ReadKey::ReadMode('noecho');
        chomp($cfg{orgKey} = <STDIN>);
        Term::ReadKey::ReadMode('restore');
        print "\n";
    }
    else {
        warn "Warning: Term::ReadKey not available; org key will be visible.\n";
        print "Org Key: ";
        chomp($cfg{orgKey} = <STDIN>);
    }
}

###############################################################################
# Command implementations
###############################################################################

sub cmd_info {
    my ($ua) = @_;
    my $path = "/organizations/$cfg{orgId}/users/$cfg{userId}";
    my $out = do_get($ua, $path);
    print $out if defined $out;
}

sub cmd_list_secrets {
    my ($ua) = @_;
    my $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
             . "/documentTypes/file.raw/documents";
    my $out = do_get($ua, $path, outputType => 'csv');
    print $out if defined $out;
}

sub cmd_store_secret {
    my ($ua, $name, $file, $info) = @_;
    die "Usage: store-secret NAME FILE [INFO]\n"
        unless defined $name && defined $file;
    die "File not found: $file\n" unless -r $file;
    my $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
             . "/documentTypes/file.raw/documents/$name";
    my $out = do_post_multipart($ua, $path, $file, $info);
    print $out if defined $out;
}

sub cmd_get_secret {
    my ($ua, $name, $outfile) = @_;
    die "Usage: get-secret NAME [OUTFILE]\n" unless defined $name;
    my $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
             . "/documentTypes/file.raw/documents/$name/content";
    my %params = (auth_params());
    my $url = append_query(base_url() . $path, %params);
    my $req = HTTP::Request->new(GET => $url);
    my $res = make_ua()->request($req);
    unless ($res->is_success) {
        warn "HTTP error: " . $res->status_line . "\n";
        warn $res->decoded_content . "\n" if $res->decoded_content;
        return;
    }
    if (defined $outfile) {
        open(my $fh, '>', $outfile) or die "Cannot write $outfile: $!\n";
        binmode $fh;
        print $fh $res->content;
        close $fh;
        print "Secret saved to: $outfile\n";
    }
    else {
        print $res->decoded_content;
    }
}

sub cmd_delete_secret {
    my ($ua, $name) = @_;
    die "Usage: delete-secret NAME\n" unless defined $name;
    my $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
             . "/documentTypes/file.raw/documents/$name";
    my $out = do_delete($ua, $path);
    print $out if defined $out;
}

sub cmd_db_list {
    my ($ua) = @_;
    my $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
             . "/documentTypes/file.csv/documents";
    my $out = do_get($ua, $path, outputType => 'csv');
    print $out if defined $out;
}

sub cmd_db_create {
    my ($ua, $name, $columns) = @_;
    die "Usage: db-create NAME col1,col2,...\n"
        unless defined $name && defined $columns;
    # The CSV header is just the column names followed by a newline
    my $csv_header = $columns . "\n";
    my $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
             . "/documentTypes/file.csv/documents/$name";
    my $out = do_post_csv_create($ua, $path, $csv_header);
    print $out if defined $out;
}

sub cmd_db_insert {
    my ($ua, $name, @col_vals) = @_;
    die "Usage: db-insert NAME col=val ...\n"
        unless defined $name && @col_vals;

    # Parse col=val pairs
    my %row;
    for my $pair (@col_vals) {
        my ($col, $val) = split /=/, $pair, 2;
        die "Bad col=val pair: $pair\n" unless defined $col && defined $val;
        $row{$col} = $val;
    }

    # First GET current content to count existing rows (determines next row index)
    my $content_path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
                     . "/documentTypes/file.csv/documents/$name/content";
    my $content = do_get($ua, $content_path, outputType => 'csv');
    return unless defined $content;

    # Count non-empty, non-header lines (header is line 1)
    my @lines = grep { /\S/ } split /\n/, $content;
    my $row_count = scalar(@lines) > 0 ? scalar(@lines) - 1 : 0;
    my $next_row  = $row_count + 1;

    my $post_path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
                  . "/documentTypes/file.csv/documents/$name"
                  . "/contentRows/$next_row";
    my $out = do_post_params($ua, $post_path, %row);
    print $out if defined $out;
}

sub cmd_db_query {
    my ($ua, $name, $row) = @_;
    die "Usage: db-query NAME [ROW]\n" unless defined $name;
    my $path;
    if (defined $row) {
        $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
              . "/documentTypes/file.csv/documents/$name"
              . "/contentRows/$row";
    }
    else {
        $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
              . "/documentTypes/file.csv/documents/$name/content";
    }
    my $out = do_get($ua, $path, outputType => 'csv');
    print $out if defined $out;
}

sub cmd_db_update {
    my ($ua, $name, $row, @col_vals) = @_;
    die "Usage: db-update NAME ROW col=val ...\n"
        unless defined $name && defined $row && @col_vals;

    my %params;
    for my $pair (@col_vals) {
        my ($col, $val) = split /=/, $pair, 2;
        die "Bad col=val pair: $pair\n" unless defined $col && defined $val;
        $params{$col} = $val;
    }

    my $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
             . "/documentTypes/file.csv/documents/$name"
             . "/contentRows/$row";
    my $out = do_put($ua, $path, %params);
    print $out if defined $out;
}

sub cmd_db_delete_row {
    my ($ua, $name, $row) = @_;
    die "Usage: db-delete-row NAME ROW\n"
        unless defined $name && defined $row;
    my $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
             . "/documentTypes/file.csv/documents/$name"
             . "/contentRows/$row";
    my $out = do_delete($ua, $path);
    print $out if defined $out;
}

sub cmd_db_delete {
    my ($ua, $name) = @_;
    die "Usage: db-delete NAME\n" unless defined $name;
    my $path = "/organizations/$cfg{orgId}/storage/$cfg{storage}"
             . "/documentTypes/file.csv/documents/$name";
    my $out = do_delete($ua, $path);
    print $out if defined $out;
}

sub cmd_audit_log {
    my ($ua) = @_;
    my $out = do_get($ua, '/transactions', outputType => 'csv');
    print $out if defined $out;
}

sub cmd_help {
    # Print the POD/comment usage block from the top of this file
    open(my $fh, '<', $0) or die "Cannot read $0: $!\n";
    my $in_header = 0;
    while (<$fh>) {
        if (/^###/) { $in_header = !$in_header; next; }
        print if $in_header;
    }
    close $fh;
}

###############################################################################
# Command dispatch
###############################################################################
my %COMMANDS = (
    'info'           => sub { my $ua = shift; cmd_info($ua) },
    'list-secrets'   => sub { my $ua = shift; cmd_list_secrets($ua) },
    'store-secret'   => sub { my ($ua, @a) = @_; cmd_store_secret($ua, @a) },
    'get-secret'     => sub { my ($ua, @a) = @_; cmd_get_secret($ua, @a) },
    'delete-secret'  => sub { my ($ua, @a) = @_; cmd_delete_secret($ua, @a) },
    'db-list'        => sub { my $ua = shift; cmd_db_list($ua) },
    'db-create'      => sub { my ($ua, @a) = @_; cmd_db_create($ua, @a) },
    'db-insert'      => sub { my ($ua, @a) = @_; cmd_db_insert($ua, @a) },
    'db-query'       => sub { my ($ua, @a) = @_; cmd_db_query($ua, @a) },
    'db-update'      => sub { my ($ua, @a) = @_; cmd_db_update($ua, @a) },
    'db-delete-row'  => sub { my ($ua, @a) = @_; cmd_db_delete_row($ua, @a) },
    'db-delete'      => sub { my ($ua, @a) = @_; cmd_db_delete($ua, @a) },
    'audit-log'      => sub { my $ua = shift; cmd_audit_log($ua) },
    'help'           => sub { cmd_help() },
);

###############################################################################
# Interactive REPL
###############################################################################
sub run_interactive {
    my ($ua) = @_;
    print "CaumeDSE interactive shell. Type 'help' for commands, 'quit' to exit.\n";
    while (1) {
        print "cdse> ";
        my $line = <STDIN>;
        last unless defined $line;
        chomp $line;
        $line =~ s/^\s+|\s+$//g;
        next unless length $line;
        last if $line eq 'quit' || $line eq 'exit' || $line eq 'q';

        # Simple shell-like tokenization (handles single/double quotes)
        my @tokens;
        while ($line =~ /("([^"]*)")|('([^']*)')|(\S+)/g) {
            if    (defined $2) { push @tokens, $2 }
            elsif (defined $4) { push @tokens, $4 }
            elsif (defined $5) { push @tokens, $5 }
        }
        next unless @tokens;

        my $cmd = shift @tokens;
        if (exists $COMMANDS{$cmd}) {
            eval { $COMMANDS{$cmd}->($ua, @tokens) };
            warn $@ if $@;
        }
        else {
            warn "Unknown command: $cmd  (type 'help' for list)\n";
        }
    }
    print "\nBye.\n";
}

###############################################################################
# Main entry point
###############################################################################

if ($cfg{interactive}) {
    # Interactive mode: prompt for credentials, then enter REPL
    prompt_credentials();
    die "userId, orgId and orgKey are required.\n"
        unless $cfg{userId} && $cfg{orgId} && $cfg{orgKey};
    my $ua = make_ua();
    run_interactive($ua);
}
else {
    # One-shot mode: command and args from ARGV
    my $cmd = shift @ARGV // 'help';

    if ($cmd eq 'help') {
        cmd_help();
        exit 0;
    }

    die "userId is required (--userId or CDSE_USER_ID).\n"  unless $cfg{userId};
    die "orgId is required (--orgId or CDSE_ORG_ID).\n"     unless $cfg{orgId};
    die "orgKey is required (--orgKey or CDSE_ORG_KEY).\n"  unless $cfg{orgKey};

    unless (exists $COMMANDS{$cmd}) {
        warn "Unknown command: $cmd\n";
        cmd_help();
        exit 1;
    }

    my $ua = make_ua();
    eval { $COMMANDS{$cmd}->($ua, @ARGV) };
    if ($@) {
        chomp(my $err = $@);
        die "$err\n";
    }
}

__END__
