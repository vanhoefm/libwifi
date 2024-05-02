# VirtIO

The `mac80211_hwsim` driver seems to be able to act as a VirtIO driver, running in the
guest VM. But there seems to be [no public backends](https://op-lists.linaro.org/archives/list/stratos-dev@op-lists.linaro.org/thread/VPLKMBWYB4PG2X5MTACUIW5SBGBP5HVF/).
These VirtIO also doesn't seem to have a control channel, so setting the channel and so on
cannot be communicated to the host. From the linked discussion:

    Neither of these have up-streamed the specification to OASIS but there
    is an implementation of the mac80211_hwsim in the Linux kernel. I found
    evidence of a plain 80211 virtio_wifi.c existing in the Android kernel
    trees. So far I've been unable to find backends for these devices but I
    assume they must exist if the drivers do!

    Debates about what sort of features and control channels need to be
    supported often run into questions about why existing specifications
    can't be expanded (for example expand virtio-net with a control channel
    to report additional wifi related metadata) or use pass through sockets
    for talking to the host netlink channel.


# Ethernet Interface as Wi-Fi

## Usage

You can add the interface as follows:

    sudo ip link add link enp0s31f6 name virtwifi0 type virt_wifi

This seems to be useful in Android simulations, see
[this Android presentation](https://lpc.events/event/4/contributions/409/attachments/321/545/Android_Virtualization.pdf)
and an [the commit adding it](https://github.com/torvalds/linux/commit/c7cdba31ed8b87526db978976392802d3f93110c).


## Properties of the interface

The virtual Wi-Fi driver only has support for a limited number of commands:

    nl80211: Subscribe to mgmt frames with non-AP handle 0x5576323b1ba0
    nl80211: Register frame type=0xd0 (WLAN_FC_STYPE_ACTION) nl_handle=0x5576323b1ba0 match=0104 multicast=0
    nl80211: Register frame command failed (type=208): ret=-95 (Operation not supported)
    nl80211: Register frame match - hexdump(len=2): 01 04
    ...
    wpa_driver_nl80211_set_key: ifindex=4 (virtwifi0) alg=0 addr=(nil) key_idx=0 set_tx=0 seq_len=0 key_len=0 key_flag=0x10 link_id=-1
    nl80211: DEL_KEY
       broadcast key
    nl80211: set_key failed; err=-95 Operation not supported
    ...
    TDLS: Driver does not support TDLS channel switching

It can perform scans like a normal Wi-Fi card:

    nl80211: Drv Event 33 (NL80211_CMD_TRIGGER_SCAN) received for virtwifi0
    virtwifi0: nl80211: Scan trigger
    virtwifi0: Event SCAN_STARTED (47) received
    virtwifi0: Own scan request started a scan in 0.000030 seconds
    EAPOL: disable timer tick
    RTM_NEWLINK: ifi_index=4 ifname=virtwifi0 wext ifi_family=0 ifi_flags=0x1003 ([UP])
    nl80211: Event message available
    nl80211: Drv Event 34 (NL80211_CMD_NEW_SCAN_RESULTS) received for virtwifi0
    virtwifi0: nl80211: New scan results available
    nl80211: Scan probed for SSID ''
    nl80211: Scan included frequencies: 2432 5240
    virtwifi0: Event SCAN_RESULTS (3) received
    virtwifi0: Scan completed in 2.079196 seconds
    nl80211: Received scan results (1 BSSes)
    virtwifi0: BSS: Start scan result update 1
    virtwifi0: BSS: Add new id 0 BSSID 7e:46:bd:4d:65:11 SSID 'VirtWifi' freq 5240
    BSS: last_scan_res_used=1/32
    virtwifi0: New scan results available (own=1 ext=0)
    virtwifi0: Radio work 'scan'@0x55763241fcc0 done in 2.079522 seconds
    virtwifi0: radio_work_free('scan'@0x55763241fcc0): num_active_works --> 0
    virtwifi0: Selecting BSS from priority group 0
    virtwifi0: 0: 7e:46:bd:4d:65:11 ssid='VirtWifi' wpa_ie_len=0 rsn_ie_len=0 caps=0x1 level=-50 freq=5240 
    virtwifi0:    skip - SSID mismatch

Status when not connected:

    [mathy@zbook-mathy ~]$ iw dev virtwifi0 info
    Interface virtwifi0
	    ifindex 4
	    wdev 0x100000001
	    addr e0:70:ea:c3:8c:5b
	    type managed
	    wiphy 1

Scan output:

    [mathy@zbook-mathy ~]$ sudo iw dev virtwifi0 scan
    BSS 7e:46:bd:4d:65:11(on virtwifi0)
	    TSF: 2896153854 usec (0d, 00:48:16)
	    freq: 5240
	    capability: ESS (0x0001)
	    signal: -50.00 dBm
	    last seen: 0 ms ago
	    Information elements from Probe Response frame:
	    SSID: VirtWifi

So it always seems to advertise one open network.

We can now use `wpa_supplicant` to connect:

    [mathy@zbook-mathy ~]$ sudo iw dev virtwifi0 info
    Interface virtwifi0
	    ifindex 4
	    wdev 0x100000001
	    addr e0:70:ea:c3:8c:5b
	    ssid VirtWifi
	    type managed
	    wiphy 1

