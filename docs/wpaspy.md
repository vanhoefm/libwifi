# Hostap Control Interface

## Background

Both the `wpa_supplicant` and `hostapd` daemon implement a
[control interface](https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html)
that can be used by external programs to control the operations of the
daemon and to get status information and event notifications.
There are multiple mechanisms to connect with this control interface. For
example, the Linux version of `wpa_supplicant` can use UNIX domain sockets
or [D-BUS](https://en.wikipedia.org/wiki/D-Bus), and the Windows version can use UDP sockets.

## Command-Line Example

An important example is that `wpa_cli` or `hostapd_cli` can be used to control
a running instance of `wpa_supplicant` or `hostapd`, respectively. For instance,
the option `ctrl_interface` in the configuration file of `wpa_supplicant`
enables the control interface:

```
ctrl_interface=wpaspy_ctrl
network={
	ssid="examplessid"
	key_mgmt=NONE
}
```

When starting `wpa_supplicant` with this configuration, it will create the directory
`wpaspy_ctrl` containing named sockets for each network interface being controlled.
You can now start `wpa_cli` with this directory as an argument:

```
wpa_cli -p wpaspy_ctrl
```

Behind the scenes, `wpa_cli` will now connect to the named sockets created by `wpa_supplicant`.
You can now issue commands and they will be forwarded to `wpa_supplicant`. Some examples are:

```
Selected interface 'wlan0'

Interactive mode

> scan
OK
<3>CTRL-EVENT-SCAN-STARTED 
<3>CTRL-EVENT-SCAN-RESULTS 
> scan_results
bssid / frequency / signal level / flags / ssid
7c:00:11:22:33:44	5500	-53	[WPA2-PSK-CCMP][WPS][ESS]	testnetwork
> status
bssid=7c:00:11:22:33:44
freq=5500
ssid=testnetwork
id=0
mode=station
wifi_generation=5
pairwise_cipher=CCMP
group_cipher=CCMP
key_mgmt=WPA2-PSK
wpa_state=COMPLETED
ip_address=192.168.0.7
p2p_device_address=80:38:fb:17:e8:64
address=80:38:fb:17:e8:64
uuid=6bdefd05-00a3-51d5-8c84-3a7517206b8b
ieee80211ac=1
> 
```

Typically, the commands typed in `wpa_cli` or `hostapd_cli` directly map to raw
commands that are forwarded to the `wpa_supplicant` or `hostapd_cli` daemon,
respectively. For instance, the command `status` causes the raw command `STATUS`
to be sent to the daemon.

## Overview of Commands

The most complete list of commands can be obtained by reading the source code:

- `wpa_supplicant`: see the function `wpa_supplicant_ctrl_iface_process` in [`wpa_supplicant/ctrl_iface.c`](https://w1.fi/cgit/hostap/tree/wpa_supplicant/ctrl_iface.c)
- `hostapd`: see the function `hostapd_ctrl_iface_receive_process` in [`hostapd/ctrl_iface.c`](https://w1.fi/cgit/hostap/tree/hostapd/ctrl_iface.c)

Notice that some control commands are only available when using the `CONFIG_TESTING_OPTIONS`
compilation flags. You can enable this flag by including the line `CONFIG_TESTING_OPTIONS=y`
inside the `.config` file when compiling `wpa_supplicant` or `hostapd`.

There's also a [command overview](https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html)
provided by the hostap documentation. These are raw commands send over the control interface.

## Python-Based Interface

The most useful application is writing Python scripts that control `wpa_supplicant` or
`hostapd` through the control interface and that optionally use [scapy](https://scapy.net/)
to inject raw frames. For instance, this approach is used in the
[Wi-Fi Testing Framework](https://github.com/domienschepers/wifi-framework), in the
[FragAttacks Tool](https://github.com/vanhoefm/fragattacks), the
[MacStealery Tool](https://github.com/vanhoefm/macstealer), and so on.

To easily connect to the control interface and send commands, you can use the
[wpaspy.py](https://w1.fi/cgit/hostap/tree/wpaspy/wpaspy.py) library that is part of the
hostap repository.

**TODO: Very basic example on starting hostapd/wpa_supplicant, connect to control interface, do basic things**

**TODO: Now reference the Wi-Fi Testing Framework GENERIC TEST CASE: get IP, packet processing**

**TODO: Now explain trigger-based approach for Wi-Fi Testing Framework**

## Extending the Control Interface

See the [Wi-Fi Testing Framework](https://github.com/domienschepers/wifi-framework/blob/master/docs/EXTENSIONS.md)
for an example on how you can extend the control interface when performing experiments
or tests using hostap.

## Interactive Requests

If wpa_supplicant needs additional information during authentication (e.g., password),
it will use a specific prefix, CTRL-REQ- (WPA_CTRL_REQ macro) in an unsolicited event
message. An external program, e.g., a GUI, can provide such information by using
CTRL-RSP- (WPA_CTRL_RSP macro) prefix in a command with matching field name.

For example, request from wpa_supplicant:
```
CTRL-REQ-PASSWORD-1-Password needed for SSID test-network
```
And a matching reply from the GUI:
```
CTRL-RSP-PASSWORD-1-secret
```
See the [hostapd overview](https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html)
for more information.
