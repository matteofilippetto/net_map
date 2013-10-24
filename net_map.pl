#!/usr/bin/perl

#################
# MODULE IMPORT #
#################

use 5.010;
use Net::Ping;
use Net::ARP;
use Net::Netmask;
use Net::NBName;
use Net::MAC::Vendor;
use warnings;
use strict;
use Getopt::Std;
use Cwd;
use File::Fetch;

#############
# VARIABLES #
#############

my %opts = ( );				# hash to collect options in
my $net = '';				# network to scan
my $cidr = '';				# ip to scan in cidr form
my $range = '';				# ip range to scan
my $format = '';			# format for export file
my $timeout = 1;			# timeout for ping
my $device = "eth0";		# device to use. eth0 as default
my $export_filename = "";	# file name for csv export
my $key = '';					# for input parameters
my $value;					# for input parameters

getopt('n:c:r:e:t:i:u:h:', \%opts);   

# options
#	-n <net>		# select network
#	-c <cidr>		# select address in cidr form
#	-r <range>		# select ip range to scan
#	-e <format>		# select format for export (only csv at the moment)
#	-t <seconds>	# select timeout for ping command
#	-i <device>		# select device to use
#	-u				# update oui.txt from standards.ieee.org
#	-h				# display usage

printf("%s", $key);

# parse options and set relevant vars
while (($key, $value) = each(%opts) ) {
	if ('n' eq $key) {
		if($value ne '') {
			$net = $value;
		} else {
			&usage;
		}
	}

	if ('c' eq $key) {
		if($value ne '') {
			$cidr = $value;
		} else {
			&usage;
		}
	}
    
	if ('r' eq $key) {
		if($value ne '') {
			$range = $value;
		} else {
			&usage;
		}
	}
    
	if ('e' eq $key) {
		if($value ne '') {
			$format = $value;
			# define export file name
			my @array_time = localtime;
			$export_filename = 'hosts_' . ($array_time[5] + 1900) . $array_time[4] . $array_time[3] . '_' . $array_time[2] . $array_time[1] . '.csv'; 
			
		} else {
			&usage;
		}
	}
    
	if ('t' eq $key) {
		if($value ne '') {
			$timeout = $value;
		} else {
			&usage;
		}
	}
    
	if ('i' eq $key) {
		if($value ne '') {
			$device = $value;
		} else {
			&usage;
		}
	}
    
	if ('u' eq $key) {
		&update_oui;
	}
}

################
# MAIN PROGRAM #
################

printf("%s", $key);

# load oui.txt into cache
if ('u' ne $key) {
	Net::MAC::Vendor::load_cache("file://" . cwd . "/oui.txt");
}

if($net ne '') {
	
	my $ip;
	my $address;
	my @ips = &list_ips(24);
	
	my $result = rindex($net, ".") + 1;
	$net = substr $net,0,$result;
	
	foreach $ip (@ips) {
		
		$address = $net . $ip;
		if($format eq '') {
			&verify_ip_screen($address, $timeout, $device);
		} else {
			&verify_ip_to_csv($address, $timeout, $device, $export_filename);
		}
	}
	
} elsif ($cidr ne '') {
	
	my $address;
	
	die $Net::Netmask::error 
	unless my $netblock = new2 Net::Netmask($cidr);
	
	my $blocksize = $netblock->size()-1;
	
	for(my $i = 1; $i <= $blocksize; $i++) {
		$address = $netblock->nth($i);
		if($format eq '') {
			&verify_ip_screen($address, $timeout, $device);
		} else {
			&verify_ip_to_csv($address, $timeout, $device, $export_filename);
		}
	}
	
} elsif ($range ne '') {
	
	my $ip = '';
	my $address = '';
	my $network = '';
	my $inizio = '';
	my $fine = '';
	my $tmp = '';
	
	my @items = split '-', $range;
	
	if(index($range, '-') != -1 && $#items == 1) {
		
		($tmp, $fine) = split('-', $range);
		$inizio = substr($tmp, rindex($tmp, '.') + 1);
		$network = substr($tmp, 0, rindex($tmp, '.'));
		for(my $ip = $inizio; $ip <= $fine; $ip++) {
			$address = $network . '.' . $ip;
			if($format eq '') {
				&verify_ip_screen($address, $timeout, $device);
			} else {
				&verify_ip_to_csv($address, $timeout, $device, $export_filename);
			}
		}
		
	} else {
		die("Invalid range.");
	}
	
} else {
	&usage;
}

exit();

############
# END MAIN #
############

#############
# FUNCTIONS #
#############

sub verify_ip_screen {

	my $rip = '';
	my $status;
	my $duration;
	my $mac_address = ''; 

	my $po = Net::Ping->new('icmp');
	
	$po->hires();
	
	($status, $duration, $rip) = $po->ping($_[0], $_[1]);
	
	if($status) {
	
		$mac_address = Net::ARP::arp_lookup($_[2],$_[0]);
		
		if($mac_address ne '') {
			printf("ip $rip is alive (return time: %.2f ms). MAC: $mac_address. Vendor: %s\n", 1000 * $duration, &get_vendor_name($mac_address));
		}
		else {
			printf("ip $rip is alive (return time: %.2f ms). MAC: N/A \n", 1000 * $duration);
		}
		
	} else {
		printf("ip $rip is NOT alive\n");
	}
	
	$po->close();
}

sub verify_ip_to_csv {

	my $rip = '';
	my $status;
	my $duration;
	my $mac_address = ''; 
	
	my $alive = 0;			# number of alive hosts
	my $no_alive = 0;		# number of not alive hosts
	
	if (!open LOG, '>>' . $_[3]) {
		die("Non posso aprire $_[3]: $!");
	}
	
	my $po = Net::Ping->new('icmp');
	
	$po->hires();
	
	($status, $duration, $rip) = $po->ping($_[0], $_[1]);
	
	if($status) {  
		$alive++;
		$mac_address = Net::ARP::arp_lookup($_[2],$_[0]);

		if($mac_address ne '') {
			printf LOG ("$rip;alive;$mac_address;%.2f;%s;\n", 1000 * $duration, &get_vendor_name($mac_address));
		}
		else {   
			printf LOG ("$rip;alive;N/A;%.2f \n", 1000 * $duration);
		}
	} else {
		$no_alive++;
		printf LOG ("$rip;not alive;N/A;" . "0" . "\n");
	}
	
	close(LOG);
	
	$po->close();
}

sub get_vendor_name {
	
	my @vendors; 
	my $vendor_name = '';
	
	@vendors = Net::MAC::Vendor::fetch_oui_from_cache(Net::MAC::Vendor::normalize_mac($_[0]));
	
	foreach my $line (@vendors) {
		my @vendor = @$line;
		$vendor_name = $vendor[0];
	}
	
	$vendor_name;
}

sub list_ips {
	
	my @return;
	
	given( $_[0] ) {
		when($_ ~~ 24) { @return = (1..254); }
#		when($_ ~~ 25) { @return = (129..254); }
#		when($_ ~~ 26) { @return = (193..254); }
		default { @return = (1..254); }
	}
	
	@return;
}

sub update_oui {
	
	my $oui_link = File::Fetch->new(uri => 'http://standards.ieee.org/develop/regauth/oui/oui.txt');
	my $oui_file = $oui_link->fetch() or die $oui_link->error;
	exit();
	
}

sub usage {
	
	print("./net_map.pl");
	print("\n -i: device to use. Example: eth1");
	print("\n -n: network. Example: -n 192.168.10.0. Implicit subnet /24");
	print("\n -c: notazione cidr. Example: -c 192.168.23.0/16");
	print("\n -r: range di ip. Example: -r 192.168.1.23-29");
	print("\n -e: export (only CSV). Example: -e csv");
	print("\n -u: update oui.txt from ieee.org");
	print("\n");
	exit();
	
}
