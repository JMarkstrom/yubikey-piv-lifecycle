# PIV
Personal Identity Verification (PIV) related assets for YubiKeys

 <h1 align="center"> YubiKey PIV "lifecycle" using Python </h1>

## Table Of Contents
  * [About](https://github.com/JMarkstrom/PIV/blob/main/README.md#about)
  * [Prerequisites](https://github.com/JMarkstrom/PIV/blob/main/README.md#prerequisites)
  * [Usage](https://github.com/JMarkstrom/PIV/blob/main/README.md#usage)
  * [Release History](https://github.com/JMarkstrom/PIV/blob/main/README.md#release-history)

## About
The **yubikey-piv.py** script exemplifies how to use Python to perform YubiKey configuration and issuance. 
With regards to issuance, the script creates a CSR that, if issued, allows for authentication into Entra ID (Azure AD).
In summary, the script can perfor the following actions/tasks:

* Change Management Key
* Set a non-trivial(!) PIN
* Set a non-trivial(!) PUK
* Create a CSR
* Perform Attestation
* Import a certificate

⚠️ This script is provided "as-is" without any warranty of any kind, either expressed or implied.

## 💻 Prerequisites
You will need to meet the following prequisites to make use of this script:

- YubiKey Manager (get it [here](https://www.yubico.com/support/download/yubikey-manager/))
- One (1) YubiKey 5 series authenticator
- An issuing Certificate Authority (CA) e.g a Microsoft PKI

## 📖 Usage
To use the script simply open a command prompt and execute: ```ykman script yubikey-piv.py```

<sub>Configuring a YubiKey using Python (example):<sub>
![animated gif showing script usage](https://i.imgur.com/Lq0vi92.gif)


**Note**: For more detail and broader context, please refer to [swjm.blog](https://swjm.blog)

## Release History
* 2023.08.14 `v1.4`
