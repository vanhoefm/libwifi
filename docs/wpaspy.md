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

## Overview of Raw Commands

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
**To easily connect to the control interface and send commands, you can use the
[wpaspy.py](https://w1.fi/cgit/hostap/tree/wpaspy/wpaspy.py) library that is part of the
hostap repository**.

As a very basic and motivating example, you can now use a Python script to start
`wpa_supplicant` and to connect to the control interface. Here the `client.conf`
file from above is used:
```python
#!/usr/bin/env python3
from wpaspy import Ctrl
import time, subprocess

# Remove old occurrences of the control interface that didn't get cleaned properly
subprocess.call(["rm", "-rf", "wpaspy_ctrl/"])

# -W parameter makes wpa_supplicant pause on startup until we connect to control interface
nic_iface = "wlan2"
cmd = ["wpa_supplicant", "-Dnl80211", "-i", nic_iface, "-c", "client.conf", "-W", "-dd"]
process = subprocess.Popen(cmd)
time.sleep(1)

# Connect to the control interface
wpaspy_ctrl = Ctrl("wpaspy_ctrl/" + nic_iface)
wpaspy_ctrl.attach()

# Example commands: disable all networks, then connect to first network in client.conf
wpaspy_ctrl.request("DISABLE_NETWORK all")
wpaspy_ctrl.request("SELECT_NETWORK 0")

# Let wpa_supplicant run for 10 seconds and then exit
time.sleep(10)
wpaspy_ctrl.request("TERMINATE")
process.wait()
```
By starting the above Python script, `wpa_supplicant` starts and automatically some
commands are sent over the control interface. This approach typically makes it
easier to perform Wi-Fi commands since you don't need to run separate commands.
You can now also combine this with the creation of monitor interface and then using
[Scapy](https://scapy.net/) to inject Wi-Fi frames.

In several experiments, you require more than simply controlling the daemon. For instance,
it may also be necessary to create and configure a monitor interface, get an IP address
using DHCP, have an event loop in the Python script to react to incoming packets and events
from the daemon, and so on. Fortunately, these extra functionalities are already provided
by the [Wi-Fi Testing Framework](https://github.com/domienschepers/wifi-framework). This
framework also relies on the control interface of hostap but already has code to handle some
of the previously mentioned tasks. Additionally, it has some extra control interface commands
that have been added to `wpa_supplicant` and `hostapd`.

Depending on the functionality that you require, there are three aways to use the Wi-Fi
Testing Framework:

1. You can **write your own Python code from scratch**, similar to the above code, but use the
   `wpa_supplicant` or `hostapd` version from the testing framework. This has as advantage
   that some extra control commands are available.
2. You can **use the framework to write [generic test cases](https://github.com/domienschepers/wifi-framework/blob/master/docs/USAGE.md#generic-test-cases)**.
   This provides code to start the daemon, send commands more reliably, and receive responses.
   However, you would for instance still need to add code to request an IP address using DHCP.
3. You can **use the [action-based test cases](https://github.com/domienschepers/wifi-framework/blob/master/docs/USAGE.md#action-based-test-cases)**.
   These allow you to perform a lot of operations automatically. For instance, the daemon gets
   started automatically, you can very easily request an IP address, you can wait for an event
   to complete, etc. The downside is that more complex scenarios are more difficult to model
   in action-based test cases.

## Extending the Control Interface

See the [Wi-Fi Testing Framework](https://github.com/domienschepers/wifi-framework/blob/master/docs/EXTENSIONS.md)
for an example on how you can extend the control interface when performing experiments
or tests using hostap.

## Events

The daemon will also send events over the control interface. One example is that, when
connecting to an Enterprise network, the following event is sent over the named socket:
```
#define 	WPA_EVENT_EAP_PEER_CERT   "CTRL-EVENT-EAP-PEER-CERT "
```
This event contains information about the certificate used by the RADIUS server of
the Enterprise Wi-Fi networks. This is sent by the function `wpas_notify_certification`
in [`wpa_supplicant/notify.c`](https://w1.fi/cgit/hostap/tree/wpa_supplicant/notify.c).
A similar event is also sent over the D-BUS control interface.

Note that [Android added its own interface to hostap](https://source.android.com/docs/core/connect/wifi-hal)
whose latest implementation is made using AIDL. For instance, in the function `wpas_notify_certification`,
the Android port of `wpa_supplicant` will call [`wpas_aidl_notify_ceritification`](https://cs.android.com/android/platform/superproject/main/+/main:external/wpa_supplicant_8/wpa_supplicant/notify.c;l=976;drc=9a47c375380b347f6eaadde0a549af066731a079).
This is then further handled in [`InsecureEapNetworkHandler.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/Wifi/service/java/com/android/server/wifi/InsecureEapNetworkHandler.java;drc=262fabad218484b6240dc1124e91e1f488d244ae;l=258)
and [`WifiConfigManager.java`](https://cs.android.com/android/platform/superproject/+/android14-qpr3-release:packages/modules/Wifi/service/java/com/android/server/wifi/WifiConfigManager.java;l=4362?q=AltSubjectMatch)
to, for instance, implement Trust-On-First-Use for Enterprise authentication by setting the
network option [`ca_cert`](https://w1.fi/cgit/hostap/tree/wpa_supplicant/wpa_supplicant.conf?h=hostap_2_11#n1251)
to the hash value extracted from the event.

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
