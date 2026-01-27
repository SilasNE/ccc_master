#! /bin/bash

echo "==============="
echo "Network Scanner"
echo "==============="

nmap -sn

$network = Read-Host "Welche IP möchtest du davon genauer scannen? "
echo "$network wird jetzt gescannt..."
nmap $network

$detailed = Read-Host "Möchtest du noch ein genaueren Port scannen? (J/N) "
if $detailed == J or j:
    $port = Read-Host "Welchen Port möchtest du scannen? "
    echo "Port $port wird jetzt gescannt..."
    nmap -p $port $network
    echo "Port $port wurde gescannt!"
else:
    echo "Geht leider nicht."

