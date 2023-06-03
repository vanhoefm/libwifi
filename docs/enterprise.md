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
