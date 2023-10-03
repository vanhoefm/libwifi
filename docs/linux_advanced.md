## Capturing 802.11n/ac/ax traffic

**TODO:**
- [Source 1](https://superuser.com/questions/1531866/802-11ax-monitor-mode-captures-very-few-packets)



## 5 GHz support

In order to inject frames on 5 GHz channels the network card being used must allow this.
Unfortunately, this is not always possible due to regulatory constraints.
To see on which channels you can inject frames you can execute `iw list` and look under Frequencies for channels that are _not_ marked as disabled, no IR, or radar detection.
Note that these conditions may depend on your network card, the current configured country, and the AP you are connected to.
For more information see, for example, the [Arch Linux documentation](https://wiki.archlinux.org/index.php/Network_configuration/Wireless#Respecting_the_regulatory_domain).

In mixed mode the Linux kernel may not allow the injection of frames even though it is allowed to send normal frames.
This is because in the function `ieee80211_monitor_start_xmit` the kernel refuses to inject frames when `cfg80211_reg_can_beacon` returns false.
As a result, Linux may refuse to inject frames even though this is actually allowed.
Making `cfg80211_reg_can_beacon` return true under the correct conditions prevents this bug.

**TODO: Reference patch that does the above.**
	
In practice, some people have found that you must first manually set the wireless network card to the 5GHz channel that the AP is operating on.
See [this GitHub issue](https://github.com/vanhoefm/fragattacks/issues/33#issuecomment-898712082) for details.


<a id="id-handling-sleep"></a>
## Handling sleep mode

Devices such as mobile phones or IoT gadgets may put their Wi-Fi radio in sleep mode to reduce energy usage.
When in sleep mode, these devices are unable to receive Wi-Fi frames, which may interfere with experiments. There are some options to try to mitigate this problem:

1. Try to disable sleep mode on the device being tested. This is the most reliable solution, but unfortunately not always possible.

2. Use the framework to create an AP and then inject frames. Most network cards will then queue injected frames until the device being tested is awake again.

3. Try a different network card to perform the tests. I found that different network cards will inject frames at (slightly) different times, and this may be the difference between injected frame properly arriving or being missed.


<a id="id-backport-drivers"></a>
## Compiling and modifying Linux drivers

**TODO:** [See their wiki](https://backports.wiki.kernel.org/index.php/Main_Page).

## Specialized Topics

### Experimenting with WPA3 and SAE-PK

#### Compiling wpa_supplicant and Hostapd

When compiling `wpa_supplicant` make sure that its `.config` file includes:

	CONFIG_SAE_PK=y
	CONFIG_IEEE80211W=y
	CONFIG_MESH=y

When compiling `hostapd` make sure that its `.config` file includes:

	CONFIG_GETRANDOM=y
	CONFIG_SAE=y
	CONFIG_SAE_PK=y
	CONFIG_DPP=y

Note that for `hostapd` we enable DPP so required dependencies are properly compiled.

<a id="hostapd-enterprise"></a>
#### Configuring Enterprise Network

The easiest way to generate certificates is using the scripts for freeradius.
We're going to use SVN to export the relevant directory from the freeradius github repository:

	# Navigate to the hostapd/ directory in the hostap repository
	cd hostapd
	svn export https://github.com/FreeRADIUS/freeradius-server/trunk/raddb/certs
	cd certs
	# Optionally change certificate parameters by editing the *.cnf files
	./bootstrap

Note that the "Server Domain" of the generated server certificate is `radius.example.org`.
This domain needs to be explicitly specified in most Wi-Fi clients.
Now update your hostapd.conf with the following parameters (by adding lines or changing existing values):

	ieee8021x=1
	eap_server=1
	eap_user_file=hostapd.eap_user
	ca_cert=certs/ecc/ca.pem
	server_cert=certs/ecc/server.pem
	private_key=certs/ecc/server.key
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


#### Configuring SAE-PK

First generate a private key:

	openssl ecparam -name prime256v1 -genkey -noout -out example_key.der -outform der

Now derive the password from it:

	cd hostapd
	make sae_pk_gen
	./sae_pk_gen example_key.der 3 SAEPK-Network

Example output:

	...
	sae_password=2udb-slxf-3ij2|pk=04e8aad54d1a121955e8703d1dfa115e:MHcCAQEEIKMP3SZEAlW9rSwTFsaR/sEyX963opsOo2QYe4G8Kcl+oAoGCCqGSM49AwEHoUQDQgAE4GuxyTkKNt0MEispu/XPxImInj+tl2ri/Jfu2mOQKb1TdNHSPs6UP+rxv5OWnezhOpjpD63Y+zjjz1yk7/iF7g==
	# Longer passwords can be used for improved security at the cost of usability:
	# 2udb-slxf-3ijn-y65k
	# 2udb-slxf-3ijn-y65x-vr2e
	# 2udb-slxf-3ijn-y65x-vr2i-6qob
	...

Now create the hostapd configuration file `hostapd.conf`:

	interface=wlan0
	ssid=SAEPK-Network

	hw_mode=g
	channel=1

	wpa=2
	wpa_key_mgmt=SAE
	rsn_pairwise=CCMP
	ieee80211w=2

	sae_groups=19
	sae_password=2udb-slxf-3ij2|pk=04e8aad54d1a121955e8703d1dfa115e:MHcCAQEEIKMP3SZEAlW9rSwTFsaR/sEyX963opsOo2QYe4G8Kcl+oAoGCCqGSM49AwEHoUQDQgAE4GuxyTkKNt0MEispu/XPxImInj+tl2ri/Jfu2mOQKb1TdNHSPs6UP+rxv5OWnezhOpjpD63Y+zjjz1yk7/iF7g==

And the corresponding client configuration `client.conf`:

	network={
		ssid="SAEPK-Network"
		sae_password="2udb-slxf-3ij2"
		key_mgmt=SAE
		ieee80211w=2
	}

### Simulated interfaces: client and AP connectivity

To test the connectivity **when using simulated interfaces** we first have to move one of the interfaces to its own namespace.
Without using namespace it [won't be possible](https://linux-wireless.vger.kernel.narkive.com/28FcVeGe/no-local-loopback-for-mac80211-hwsim-test-setup) to send and recieve ping requests between two interfaces on the same system.

So we first execute the AP in its own namespace:

	# Create a network namspace called "apnet" and move wlan0 to it
	ip netns add apnet
	PHYID=$(iw dev wlan0 info | grep wiphy | cut -d' ' -f2)
	iw phy phy$PHYID set netns name apnet

	# Execute hostapd in this namesace
	ip netns exec apnet hostapd -dd -K hostapd.conf

Then we start the client normally:

	wpa_supplicant -D nl80211 -i wlan1 -c client.conf -dd -K

Finally we can configure the IP addresses of both the client and the AP and send ICMP pings between them:

	# Configure IP addresses
	ip netns exec apnet ip addr add 192.168.100.1/24 dev wlan0
	ip addr add 192.168.100.2/24 dev wlan1
	# From the client ping the AP
	ping 192.168.100.1
	# From the AP ping the client
	ip netns exec apnet ping 192.168.100.2

The Wi-Fi traffic can be monitored on the `hwsim0` interface which captures packets on all channels.
You may have to manually bring this interface up before you can use it:

	ifconfig hwsim0 up

Note that `hwsim0` captures _all_ frames over all channels and all interface.
The `hwsim0` interface cannot be used to inject packets, it can only be used to monitor for packets.

You can also capture traffic on the `wlan0` and `wlan1` interfaces.
That will show the packets at the network layer.
If you want to capture packets on `wlan0` in this example you have to run Wireshark in the proper network namespace:

	ip netns exec apnet wireshark

Sometimes it may be usefull to disable or override the MAC address randomization of your operating system when performing tests.
You can either disable this in your network manager or manually set the MAC address of an interface:

	sudo macchanger -m 00:11:22:33:44:44 wlan0
