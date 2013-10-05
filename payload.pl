#!/usr/bin/perl

use strict;
use warnings;


if(defined($ARGV[0]) == 0 || defined($ARGV[1]) == 0) 
{
	print("Usage : $0 <number of column> <size of column name>\n"); 
	exit(1); 
}

my ($number_column, $length_column_string, $char_buffer, $column, $column_hex) = ($ARGV[0],$ARGV[1],0,0,0);
my (@columns, @columns_hex) = ();
my @charset = qw "A Z E R T Y U I O P Q S D F G H J K L M W X C V B N 1 2 3 4 5 6 7 8 9 0 a z e r t y u i o p q s d f g h j k l m w x c v b n";

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

print "Payload with $number_column column(s) ($length_column_string chars) : $column\n";
print "Payload (hex mode) with $number_column column(s) ($length_column_string chars) : $column_hex\n";

