# epoxy

SmartBox-compatible open source tool for signing ePorezi tax forms.

## DISCLAIMER

This tool is provided as-is under the MIT License. Please note:

* This software is provided without warranty of any kind. Project contributors are not responsible for any tax liabilities, penalties, damages or other consequences that may arise from using this tool.

* This project is not affiliated with the Serbian Tax Administration (Poreska Uprava).

## Build

```bash
cargo build
```

Without GTK4 support:
```bash
cargo build --no-default-features
```

## Setup

Only Linux systems are currently supported.

### Install library dependencies

- `libnss3`
- `libxml2`
- `libxmlsec1`

### Install PKCS#11 module

Install the module for your token.

#### 1. Serbian ID card

Unofficial module: https://github.com/ubavic/srb-id-pkcs11

- Download from [GitHub](https://github.com/ubavic/srb-id-pkcs11/releases)

  ```bash
  curl -L -O https://github.com/ubavic/srb-id-pkcs11/releases/download/v0.3.0/libsrb-id-pkcs11.so.0.3.0
  sudo mkdir -p /usr/lib/pkcs11
  sudo cp libsrb-id-pkcs11.so.0.3.0 /usr/lib/pkcs11/libsrb-id-pkcs11.so
  ```

- (Arch Linux) Install using [AUR package](https://aur.archlinux.org/packages/srb-id-pkcs11-git)
    ```bash
    paru -Syu srb-id-pkcs11-git
    ```

Enable `pcscd` service:
```
sudo systemctl enable pcscd
sudo systemctl start pcscd
```


### Add module to NSS database

This step is required on Arch but can be optional on other distros. Some distros already come with NSS + p11-kit preconfigured.

`-mechanisms FRIENDLY` tells NSS not to prompt for PIN when querying certificates. It shouldn't be used if your token does not allow passwordless access to public objects.

**Option 1.** Add the PKCS#11 module directly

```bash
modutil -dbdir /home/{user}/.pki/nssdb -add "srb-id-pkcs11" -libfile /usr/lib/pkcs11/libsrb-id-pkcs11.so -mechanisms FRIENDLY
```

**Option 2.** Use p11-kit proxy
```bash
modutil -dbdir /home/{user}/.pki/nssdb -add "p11-kit" -libfile /usr/lib/libp11-kit.so -mechanisms FRIENDLY
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

Example systemd unit files can be found [here](epoxy/examples/systemd).

```
systemctl --user enable epoxy.socket
systemctl --user start epoxy.socket
```

### ePorezi login and signing

For testing, use the [ePorezi test environment](https://test.purs.gov.rs). The OLZ tax form is the simplest to start with.

**DO NOT enter your PIN on the ePorezi login page**. As of 2026-02-14, PINs are being leaked to ePorezi servers.

![demo](epoxy/examples/demo.gif)
