package App::Netdisco::SSHCollector::Platform::IOSXE;

=head1 NAME

App::Netdisco::SSHCollector::Platform::IOSXE

=head1 DESCRIPTION

Collect ARP entries from Cisco IOS-XE devices. Where 'show ip arp vrf all' is not
available, VRFs are enumerated and ARP is collected per VRF.

=cut

use strict;
use warnings;

use Dancer ':script';
use Expect;
use NetAddr::MAC qw/mac_as_ieee/;
use Moo;

sub arpnip {
    my ($self, $hostlabel, $ssh, $args) = @_;
    debug "$hostlabel $$ arpnip()";

    my ($pty, $pid) = $ssh->open2pty;
    unless ($pty) {
        warn "unable to run remote command [$hostlabel] " . $ssh->error;
        return ();
    }

    my $exp = Expect->init($pty);
    $exp->raw_pty(1);

    my $prompt  = qr/[>#]\s*$/;   # IOS-XE exec prompt
    my $timeout = ($args && $args->{timeout}) ? $args->{timeout} : 30;

    my ($pos, $err, $match, $before, $after);

    ($pos, $err, $match, $before, $after) = $exp->expect($timeout, -re => $prompt);

    $exp->send("terminal length 0\n");
    ($pos, $err, $match, $before, $after) = $exp->expect($timeout, -re => $prompt);

    my @arpentries;
    my %seen;

    # optional stats to report once at end
    my %stats = ( global => 0, vrf => {} );

    my $parse_arp_text = sub {
        my ($text, $bucket) = @_;
        my $added = 0;

        for my $line (split /\r?\n/, ($text // '')) {
            next if !$line || $line =~ /^\s*$/;
            next if $line =~ /^\s*Protocol\s+Address\s+Age/i;

            my ($ip)  = $line =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
            my ($mac) = $line =~ /([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})/i;
            next unless $ip && $mac;

            my $key = lc("$ip|$mac");
            next if $seen{$key}++;

            push @arpentries, { ip => $ip, mac => mac_as_ieee($mac) };
            ++$added;
        }

        # count only newly-added entries (post-dedupe)
        if (defined $bucket) {
            if ($bucket eq 'global') { $stats{global} += $added; }
            else                     { $stats{vrf}{$bucket} = ($stats{vrf}{$bucket} || 0) + $added; }
        }
    };

    # global/default ARP
    debug "$hostlabel $$ arpnip() collecting ARP from [global]";
    $exp->send("show ip arp\n");
    ($pos, $err, $match, $before, $after) = $exp->expect($timeout, -re => $prompt);
    $parse_arp_text->($before, 'global');

    # enumerate VRFs
    $exp->send("show vrf\n");
    ($pos, $err, $match, $before, $after) = $exp->expect($timeout, -re => $prompt);

    my @vrfs;
    for my $line (split /\r?\n/, ($before // '')) {
        last if $line =~ /^\s*Platform iVRF Name/i;
        next if $line =~ /^\s*$/;
        next if $line =~ /^\s*Name\s+Default RD/i;
        next if $line =~ /^\s*-+\s*$/;

        if ($line =~ /^\s+(\S+)\s+(\S+)\s+(\S+)/) {
            my $vrf = $1;
            next if lc($vrf) eq 'default';
            push @vrfs, $vrf;
        }
    }

    debug "$hostlabel $$ arpnip() detected " . scalar(@vrfs) . " VRFs";

    # per-VRF ARP
    for my $vrf (@vrfs) {
        debug "$hostlabel $$ arpnip() collecting ARP from [vrf:$vrf]";
        $exp->send("show ip arp vrf $vrf\n");
        ($pos, $err, $match, $before, $after) = $exp->expect($timeout, -re => $prompt);
        $parse_arp_text->($before, $vrf);
    }

    # exit
    $exp->send("exit\n");
    $exp->hard_close();

    # end-of-run summary only
    my $total = scalar(@arpentries);
    my @parts = ("global=$stats{global}");
    for my $v (sort keys %{ $stats{vrf} }) {
        push @parts, "$v=$stats{vrf}{$v}";
    }
    debug "$hostlabel $$ arpnip() summary: total=$total (" . join(', ', @parts) . ")";

    return @arpentries;
}

1;
