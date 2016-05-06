#!/usr/bin/perl

# Author: Mark Boger

# Work in progress

use warnings;
use strict;

use Net::SSH::Expect;

my $password    = 'PASSWORD HERE';
my $host        = 'HOST HERE'

my $ssh = Net::SSH::Expect->new(
    host        => $host,
    password    => $password,
    user        => "root",
    raw_pty     => 1,
    timeout     => 5
);


eval {
    $ssh->login();
    $ssh->connect();
};

my $output = $ssh->exec("ls ~");

print $output;


