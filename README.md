# epoxy

SmartBox-compatible open source tool for signing ePorezi tax forms.

## DISCLAIMER

This tool is provided as-is under the MIT License. Please note:

* This software is provided without warranty of any kind. Project contributors are not responsible for any tax liabilities, penalties, damages or other consequences that may arise from using this tool.

* This project is not affiliated with the Serbian Tax Administration (Poreska Uprava).

## Quick start

### Arch Linux

```bash
# Install PKCS#11 module(s) - example for Serbian ID card
paru -Syu srb-id-pkcs11-git
sudo systemctl enable pcscd.socket
sudo systemctl start pcscd.socket

# Add p11-kit proxy module to NSS
modutil -dbdir $HOME/.pki/nssdb -add "p11-kit" -libfile /usr/lib/libp11-kit.so -mechanisms FRIENDLY
modutil -dbdir $HOME/.pki/nssdb -list

# Install epoxy
paru -Syu epoxy-git
systemctl --user enable epoxy.socket
systemctl --user start epoxy.socket
```

## Build

```bash
# All features
cargo build

# Without GTK4, systemd support
cargo build --no-default-features
```

## Setup

Only Linux systems are currently supported.

### Install library dependencies

- `libnss3`
- `libxml2`
- `libxmlsec1`
- `gtk4` (for `ui-gtk4` feature)

### Install PKCS#11 module

Install the module for your token.

#### 1. Serbian ID card

Unofficial module setup guide: https://github.com/ubavic/srb-id-pkcs11/blob/main/README.md

### Add module to NSS database

This step is required on Arch but can be optional on other distros. Some distros already come with NSS + p11-kit preconfigured.

`-mechanisms FRIENDLY` tells NSS not to prompt for PIN when querying certificates. It shouldn't be used if your token does not allow passwordless access to public objects.

**Option 1.** Add the PKCS#11 module directly

```bash
modutil -dbdir $HOME/.pki/nssdb -add "srb-id-pkcs11" -libfile /usr/lib/pkcs11/libsrb-id-pkcs11.so -mechanisms FRIENDLY
```

**Option 2.** Use p11-kit proxy
```bash
modutil -dbdir $HOME/.pki/nssdb -add "p11-kit" -libfile /usr/lib/libp11-kit.so -mechanisms FRIENDLY
```

## Usage

Run with default settings:

```bash
epoxy
```

Print help:

```bash
epoxy --help
```


### Systemd service

Systemd unit files can be found [here](epoxy/systemd).

```
systemctl --user enable epoxy.socket
systemctl --user start epoxy.socket
```

### ePorezi login and signing

For testing, use the [ePorezi test environment](https://test.purs.gov.rs). The OLZ tax form is the simplest to start with.

**DO NOT enter your PIN on the ePorezi login page**. As of 2026-02-14, PINs are being leaked to ePorezi servers.

![demo](assets/demo.gif)
