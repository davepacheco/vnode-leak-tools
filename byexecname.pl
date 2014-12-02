#!/usr/bin/perl -W

use strict;
use Data::Dumper qw/Dumper/;

# execname -> array of (hold/rele, stack) tuples
my $stacks = {};
# execname -> array of (hold/rele, unique stack, count) tuples
my $aggstacks = {};
# execname -> net count of holds minus releases
my $netbypsargs = {};
# dtrace errors
my $nerrors = 0;
# some lines are garbled by intermixed dtrace(1M) stderr output
my $ngarbled = 0;

#
# We support three modes:
#
#    procsonly		only prints net change in hold by psargs
#
#    top		prints all stack traces for psargs having count > 0
#
#    all		prints all stack traces by count
#
my $mode = shift @ARGV || 'procsonly';

# if true, ignore user stacks entirely
my $ignoreuser = 1;

#
# Run through the entire file and keep track of $stacks, a mapping of "psargs"
# to an array of (hold/rele) and (stack) tuples.
#
my $stack = '';		# current stack
my $header;		# header row for this event
my $inuser = -1;	# in the user stack trace
my $line = 0;
while (<>) {
	++$line;

	if (/^dtrace:/) {
		$nerrors++;
		next;
	}

	if (/^\s+/ && $_ !~ /^$/) {
		if (defined($header) && ($inuser < 1 || $ignoreuser == 0)) {
			$stack .= $_;
		}

		next;
	}

	if (/^$/) {
		$inuser++;

		if (defined($header) && ($inuser < 1 || $ignoreuser == 0)) {
			$stack .= $_;
		}

		next;
	}

	if ($_ !~ /^\d+/) {
		$ngarbled++;
		next;
	}

	if (defined($header)) {
		if (not exists($stacks->{$header->{psargs}})) {
			$stacks->{$header->{psargs}} = [];
		}

		push @{$stacks->{$header->{psargs}}}, {
		    'first' => $header->{start_line},
		    'kind' => $header->{kind},
		    'stack' => $stack
		};
		$header = undef;
		$stack = '';
		$inuser = -1;
	}

	chomp;
	my @parts = split(/\s+/, $_, 6);
	if (not defined $parts[1] or
	    ($parts[1] ne 'vn-hold' and $parts[1] ne 'vn-rele')) {
		next;
	}

	if ($parts[4] ne '(/zones/1787b772-2f7c-494a-bcd4-012be87af062/root)') {
		next;
	}

	$header = {
	    'start_line' => $line,
	    'kind' => $parts[1],
	    'psargs' => $parts[5]
	};

	if ($header->{kind} eq 'vn-hold') {
		$netbypsargs->{$header->{psargs}}++;
	} else {
		$netbypsargs->{$header->{psargs}}--;
	}
}

printf("finished processing (%d errors, %d garbled)\n", $nerrors, $ngarbled);

#
# Now uniquify the stacks for each execname.
#
while (my ($psargs, $execstacks) = each (%$stacks)) {
	my $dedup = {
	    'vn-hold' => {},
	    'vn-rele' => {}
	};

	foreach my $seenstack (@$execstacks) {
		if (not exists
		    $dedup->{$seenstack->{kind}}{$seenstack->{stack}}) {
			$dedup->{$seenstack->{kind}}{$seenstack->{stack}} = {
			    first => $seenstack->{first},
			    count => 0
			};
		}

		$dedup->{$seenstack->{kind}}{$seenstack->{stack}}{count}++;
	}

	$aggstacks->{$psargs} = [];
	while (my ($kind, $bystack) = each (%$dedup)) {
		while (my ($stacktrace, $info) = each (%$bystack)) {
			push @{$aggstacks->{$psargs}}, {
			    kind => $kind,
			    first => $info->{first},
			    stack => $stacktrace,
			    count => $info->{count}
			};
		}
	}

	@{$aggstacks->{$psargs}} = sort {
		return ($b->{count} <=> $a->{count}) or
		    ($a->{kind} cmp $b->{kind});
	} @{$aggstacks->{$psargs}}
}

my @allpsargs = sort {
	$netbypsargs->{$b} <=> $netbypsargs->{$a}
} keys %$netbypsargs;
foreach my $psargs (@allpsargs) {
	if ($mode eq 'top' and $netbypsargs->{$psargs} <= 0) {
		last;
	}

	if ($mode ne 'procsonly') {
		printf("COUNT  PSARGS\n");
	}

	printf("%5d %s\n", $netbypsargs->{$psargs}, $psargs);

	if ($mode eq 'procsonly') {
		next;
	}

	foreach my $stackentry (@{$aggstacks->{$psargs}}) {
		printf("        %s (%3d times, first at line %d)",
		    $stackentry->{kind}, $stackentry->{count},
		    $stackentry->{first});
		printf("%s\n", $stackentry->{stack});
	}
}
