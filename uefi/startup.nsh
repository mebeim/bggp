echo -off

# Change disk
FS0:

# Load network stack
load SnpDxe.efi
load MnpDxe.efi
load ArpDxe.efi
load RngDxe.efi
load Ip4Dxe.efi
load Dhcp4Dxe.efi

# Get an IP (takes a few seconds)
ifconfig -s eth0 dhcp

# Meanwhile keep loading rest of network stack
load Udp4Dxe.efi
load TcpDxe.efi
load DnsDxe.efi
load TlsDxe.efi
load HttpDxe.efi
load HttpUtilitiesDxe.efi

echo ~
echo You should see all "Success" messages above
echo ~
echo Now wait for eth0 to get a DHCP lease... should take max 5s
echo Check with the ifconfig command (see 'help ifconfig')
echo When it gets one you can run my BGGP5 UEFI app
echo ~
echo The TAB key works for auto completion
echo Use CTRL+H for backspace and CTRL+C to exit when done
echo -on
