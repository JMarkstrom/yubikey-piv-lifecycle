<h1 align="center"> YubiKey PIV "lifecycle" using Python</h1>

## ℹ️ About
The **yubikey-piv.py** script exemplifies how to use Python to perform YubiKey configuration and issuance of a PIV credential. 
With regards to issuance, the script creates a Certificate Signing Request (CSR) that, if issued, allows for authentication into Entra ID (Azure AD).

In summary, the script can perform the following actions/tasks:

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
- One (1) YubiKey 5 series authenticator (with PIV support)
- An issuing Certificate Authority (CA) e.g a Microsoft PKI

## 📖 Usage
To use the [script](https://github.com/JMarkstrom/PIV/raw/main/yubikey-piv.py):

1. Simply open a command prompt and execute: ```ykman script yubikey-piv.py```
2. In the main menu, select an option and follow on-screen instructions.

Option ```1```: **Configure YubiKey**:

![](/images/configure-yubikey-piv-applet.gif)

Option ```2```: **Create a CSR**:

![](/images/create-csr-for-yubikey.gif)

Option ```3```: **Validate attestation**:

![](/images/validate-yubikey-attestation.gif)

Option ```4```: **Import certifcate**:

![](/images/import-certificate-to-yubikey.gif)


**Note**: For more detail and broader context, please refer to [swjm.blog](https://swjm.blog/fc967d06d4b0)

## 🥅 Roadmap
Possible improvements includes:
- Improve CSR to better match Microsoft domain and Entra ID requirements

## 🥷🏻 Contributing
You can help by getting involved in the project, _or_ by donating (any amount!).   
Donations will support costs such as domain registration and code signing (planned).

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif)](https://www.paypal.com/donate/?business=RXAPDEYENCPXS&no_recurring=1&item_name=Help+cover+costs+of+the+SWJM+blog+and+app+code+signing%2C+supporting+a+more+secure+future+for+all.&currency_code=USD)

## 📜 Release History
* 2025.03.06 `v2.3` Display of attested metadata
* 2024.06.04 `v2.2` YubiKey fw 5.7+ support
* 2023.09.06 `v2.0` Various improvements
* 2023.08.14 `v1.0` first release
