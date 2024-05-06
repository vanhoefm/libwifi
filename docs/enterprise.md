# Configuring Enterprise Networks

The easiest way to generate certificates is using the scripts for freeradius.
We're going to use SVN to export the relevant directory from the freeradius github repository:

	# Navigate to the hostapd/ directory in the hostap repository
	cd hostapd
	svn export https://github.com/FreeRADIUS/freeradius-server/trunk/raddb/certs
	cd freeradius-server/raddb/certs
	# Optionally change certificate parameters by editing the *.cnf files
	./bootstrap

Note that the "Server Domain" of the generated server certificate is `radius.example.org`.
This domain needs to be explicitly specified in most Wi-Fi clients.
Now update your hostapd.conf with the following parameters (by adding lines or changing existing values):

	ieee8021x=1
	eap_server=1
	eap_user_file=hostapd.eap_user
	ca_cert=freeradius-server/raddb/certs/ecc/ca.pem
	server_cert=freeradius-server/raddb/certs/ecc/server.pem
	private_key=freeradius-server/raddb/certs/ecc/server.key
	private_key_passwd=whatever
	wpa=2
	wpa_key_mgmt=WPA-EAP
	rsn_pairwise=CCMP

Where a simple `hostapd.eap_user` file would be:

	*		PEAP
	# Phase 2 (tunnelled within EAP-PEAP or EAP-TTLS) users
	"mathy"	MSCHAPV2	"password"	[2]

Note that the `[2]` at the end of the last line is essential! This specifies that MSCHAPv2
can be used as an internal authentication mechanism within a (PEAP) tunnel.


# Disabling TLS encryption in Hostapd and wpa_supplicant

When trying to understand (or experiment with) WPA2/3 Enterprise, can it can be useful to disable TLS encryption.
This will allow you to see the plaintext bytes that are exchanged inside the PEAP/TLS/.. tunnel. You can configure
`Hostapd` to disable TLS encryption by adding the following line to `hostapd.conf`:

```
openssl_ciphers=eNULL:@SECLEVEL=0
```

You can use the same line to disable TLS encryption in `wpa_supplicant`:

```
network={
  ssid="experiment"
  ...
  openssl_ciphers="eNULL:@SECLEVEL=0"
}
```

You can now start `Hostapd` and connect to it with `wpa_supplicant`. In Wireshark you can now see the plaintext bytes
that are exchanged in the TLS tunnel.
