For basic information see [kernel documentation](https://iwd.wiki.kernel.org/gettingstarted)
and the [IWD documentation of Arch Linux](https://wiki.archlinux.org/title/iwd).

# Compiling IWD and starting it

Compilation instructions:

	git clone git://git.kernel.org/pub/scm/libs/ell/ell.git
	git clone git://git.kernel.org/pub/scm/network/wireless/iwd.git
	sudo apt install libtool libreadline-dev libdbus-glib-1-dev python3-docutils subversion
	cd iwd
	./bootstrap
	./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc --disable-systemd-service
	make

Starting IWD now would give problems with D-Bus:

	mathy@mathy-VirtualBox:~/wifi/iwd$ sudo ./src/iwd 
	Wireless daemon version 1.30
	Name request failed
	D-Bus disconnected, quitting...

We need to let systemd know how to handle iwd D-Bus message and permissions:

	# copy src/iwd-dbus.conf to $DATADIR/dbus-1/system.d
	# -m : then chmod the new file to 644
	# -c : this parameter is apparently ignored
	sudo /usr/bin/install -c -m 644 src/iwd-dbus.conf `pkg-config --variable=datadir dbus-1`/dbus-1/system.d

After this it's important to reboot. Otherwise the updatedated D-Bus config may not be loaded.
Now we can start IWD:

	# Disable Wi-Fi in your network manager
	sudo modprobe mac80211_hwsim radios=4
	sudo rfkill unblock wifi
	sudo ./src/iwd -i wlan1

In a second terminal we can execute the following to control the IWD client:

	sudo ./client/iwctl

Execute `help` for a list of commands.


# Enterprise networks

The [IWD Arch Linux](https://wiki.archlinux.org/title/iwd) documentation contains examples how to configure networks.
For interprise networks, IWD supports loading `.pem` files but not `.crt` files, and it currently only supports RSA certificates (not ECC).

