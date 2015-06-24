#!/bin/sh
#Script to install frubee
#Run as root
#Created by Antonio Riontino

DIR_FRUBEE=$(cd `dirname $0` && pwd -P)
cd $DIR_FRUBEE

g++ -w -Wall -o frubee frubee.cc -lpcap ||
{  
	echo "Compilation error"
	exit
}

sudo cp -f $DIR_FRUBEE/frubee /usr/bin/ ||
{  
	echo "Copy error 1"
	exit
}

sudo cp -f $DIR_FRUBEE/etc/* /etc ||
{  
	echo "Copy error 2"
	exit
}

echo "Installation complete."
echo "Run:"
echo "sudo frubee \"0\" \"0\" 0 0 0"