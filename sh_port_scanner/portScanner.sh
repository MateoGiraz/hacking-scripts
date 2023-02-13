#!bin/bash

#Colours
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"

# ./portScanner.sh <ip-addres>

if [ $1 ]; then
	echo -e "${blueColour}[+] Comenzando escaneo de puertos...${endColour}"
	ip_adress=$1
	for port in $(seq 1 65535); do
		timeout 0.1 bash -c "echo '' > /dev/tcp/$ip_adress/$port" 2>/dev/null && echo -e  "[+] El puerto $port está abierto"
	done; wait
else
	echo -e "${redColour}[!] Uso: ./portScanner.sh <Direccion_IP>${endColour}"
	exit 1
fi 