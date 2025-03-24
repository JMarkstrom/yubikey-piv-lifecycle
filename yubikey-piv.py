######################################################################
# YubiKey PIV configuration and issuance                    
######################################################################
# version: 2.4
# last updated on: 2025-03-24 by Jonas Markström
# see readme.md for more info.
#
# DEPENDENCIES: 
#   - YubiKey Manager (ykman) must be installed on the system
#
# LIMITATIONS/ KNOWN ISSUES: N/A
# 
# USAGE: ykman script yubikey-piv.py
#
# BSD 2-Clause License                                                             
# Copyright (c) 2025, Jonas Markström 
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
######################################################################

# Standard library imports
import sys
import os
import random
import time
import urllib.request
import binascii
import logging

# Third-party imports
import click
from yubikit.piv import (
    PivSession,
    SLOT,
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    DEFAULT_MANAGEMENT_KEY,
)
from yubikit.core import NotSupportedError
from ykman.piv import sign_csr_builder 
from ykman import scripting as s
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import (
    oid,
    CertificateSigningRequestBuilder,
    NameAttribute,
    ObjectIdentifier,
    OtherName,
    BasicConstraints,
    KeyUsage,
    ExtendedKeyUsage,
    SubjectAlternativeName,
    RFC822Name,
)

# Default PIN and PUK values for the YubiKey PIV applet
DEFAULT_PIN = "123456"
DEFAULT_PUK = "12345678"

# Use slot 9A (authentication)
slot = SLOT.AUTHENTICATION

# Key type will be RSA 2048
key_type = KEY_TYPE.RSA2048 # TODO: Make this detectable!


######################################################################################################################################
# CONFIGURE THE YUBIKEY (OPTION 1)                                                                                        #   
######################################################################################################################################

# Function to check for trivial PIN or PUK selection
def is_trivial(value):
    value_str = str(value)

    # Check if all digits are the same (e.g.: "000000")
    if all(digit == value_str[0] for digit in value_str):
        return True

    # Check if digits are incremental (e.g.: "123456")
    incremental_pattern = ''.join(str(i) for i in range(int(value_str[0]), int(value_str[0]) + len(value_str)))
    if value_str == incremental_pattern:
        return True

    # Check if digits are decremental (e.g.: "654321")
    decremental_pattern = ''.join(str(i) for i in range(int(value_str[0]), int(value_str[0]) - len(value_str), -1))
    if value_str == decremental_pattern:
        return True

    return False

def configure_yubikey():
    click.clear()

    # We should warn the user on the effects of resetting the PIV applet!
    click.secho("   ________________________________________________________________________________________________   ", bg="yellow")
    click.secho("  |                                                                                                |  ", bg="yellow")
    click.secho("  |                                            WARNING!                                            |  ", bg="yellow")
    click.secho("  | This option will *reset* the YubiKey PIV applet and any existing certificate credential on     |  ", bg="yellow")
    click.secho("  | the YubiKey will be lost. FIDO2, U2F, OATH and other non-PIV credentials are not affected.     |  ", bg="yellow")
    click.secho("  |                                                                                                |  ", bg="yellow")
    click.secho("  |________________________________________________________________________________________________|  ", bg="yellow")
    click.secho("                                                                                                      ", bg="yellow")

    # Prompt user to continue
    def continue_or_exit():
        if click.confirm("Do you want to continue?", default=True):
            click.clear()
        else:
            click.echo("Exiting the program...")
            # Perform cleanup or any necessary steps before exiting
            raise SystemExit

    continue_or_exit()
    click.clear()

    # Connect to a YubiKey
    yubikey = s.single()

    # Establish a PIV session
    piv = PivSession(yubikey.smart_card())

    '''
    # Get firmware version for comparison e.g determine if a feature is supported...
    version_info = yubikey.info.version
    fw = f"{version_info.major}.{version_info.minor}.{version_info.patch}"
    '''

    # Reset the PIV applet
    piv.reset()

    # MANAGEMENT KEY
  
    # Check if YubiKey takes TDES or AES Management key
    """
    If there is no metadata support, then the YubiKey uses TDES.
    Otherwise we use the metadata to determine what key type to use.
    """
    try:
        mgmt_key_type = piv.get_management_key_metadata().key_type
    except NotSupportedError:
        print("NotSupportedError")
        mgmt_key_type = MANAGEMENT_KEY_TYPE.TDES

    # Unlock with the management key
    piv.authenticate(mgmt_key_type,(DEFAULT_MANAGEMENT_KEY))

    # Define hex_key with a default value of None
    hex_key = None

    # Prompt user
    create_random_key = click.confirm("Do you want us to create a *randomized* Management Key for you?", default=True)
    if create_random_key:
        # Generate a random Management Key
        hex_key = os.urandom(24).hex()
    else:
        
        # Prompt user to set a new Management Key (48 digits)
        while True:
            # TODO: confirm hexadecimal conversion
            hex_key = click.prompt("Please enter a new Management Key (48 hex digits)", hide_input=False)
            try:
                int(hex_key, 16)  # Make sure format is valid
                if len(hex_key) == 48:
                    break
                else:
                    click.secho("⛔ Invalid Management Key length. Please enter a key of 48 hex digits.", fg="red")
                    continue
            except ValueError:
                     click.secho("⛔ The Management Key must be hexadecimal. Please try again!", fg="red")
                     continue

            break

    # Set new management key from random key or user input key
    piv.set_management_key(mgmt_key_type, bytes.fromhex(hex_key))
   
    click.clear()

    # PUK
    # TODO: check for trivial PUKs
    create_random_puk = click.confirm(
        "Do you want us to create a *randomized* PUK for you?", default=True
    )

    if create_random_puk:
        # Generate a random 8 digit PUK
        puk = str(random.randint(00000000, 99999999)).rjust(8, "0")
    else:
        # Prompt user to set a new PUK (8 digits)
        while True:
            puk = click.prompt("Please enter a new PUK (8 digits)", hide_input=False)
            if not puk.isdigit():
                click.secho("⛔ The PUK must be numeric. Please try again!", fg="red")
            elif len(puk) != 8:
                click.secho("⛔ Invalid PUK length. Please enter a PUK of 8 digits.", fg="red")
            elif is_trivial(puk): # Check selected user input for triviality!
                click.secho("⛔ The provided PUK is too easy to guess! Please choose a non-trivial PUK!", fg="red")
            else:
                break

    piv.change_puk(DEFAULT_PUK, puk)

    click.clear()

    
    # PIN

    # Prompt user to set a new PIN (6-8 digits)
          
    while True:
        pin = click.prompt("Please enter a new PIN (6-8 digits)", hide_input=False)
        if not pin.isdigit():
            click.secho("⛔ The PIN must be numeric. Please try again!", fg="red")
        elif len(pin) < 6 or len(pin) > 8:
            click.secho("⛔ Invalid PIN length. Please enter a PIN between 6 and 8 digits.", fg="red")         
        elif is_trivial(pin): # Check selected user input for triviality!
            click.secho("⛔ The provided PIN is too easy to guess! Please choose a non-trivial PIN!", fg="red")
        else:
            break

    piv.change_pin(DEFAULT_PIN, pin)

    click.clear()


    # Inform the user
    click.echo("Please note the following YubiKey details:\n")
    click.echo("-----------------------------------------------------------------------------")
    click.echo(f"YubiKey device info:   {yubikey}")
    click.echo(f"Management Key:        {hex_key}")
    click.echo(f"PIN:                   {pin}")
    click.echo(f"PUK:                   {puk}")
    click.echo("=============================================================================")
    click.echo("")
    # Return to menu system
    click.pause("\nPress any key to return to the main menu.")
    click.clear()


######################################################################################################################################
# CREATE A CSR (OPTION 2)                                                                                               #   
######################################################################################################################################

def create_csr():
    click.clear()

    # Inform the user
    click.secho("   ________________________________________________________________________________________________   ", bg="blue")
    click.secho("  |                                                                                                |  ", bg="blue")
    click.secho("  |                                            INFO                                                |  ", bg="blue")
    click.secho("  | This option will create Certificate Signing Request (CSR) based on user input. The script      |  ", bg="blue")
    click.secho("  | will output the CSR as well as necessary artifacts to support Attestation (optional task).     |  ", bg="blue")
    click.secho("  |                                                                                                |  ", bg="blue")
    click.secho("  |________________________________________________________________________________________________|  ", bg="blue")
    click.secho("                                                                                                      ", bg="blue")

    # Prompt user to continue
    def continue_or_exit():
        if click.confirm("Do you want to continue?", default=True):
            click.clear()
        else:
            click.echo("Exiting the program...")
            # Perform cleanup or any necessary steps before exiting
            raise SystemExit

    continue_or_exit()
    click.clear()

    # Connect to a YubiKey
    yubikey = s.single()

    # Establish a PIV session
    piv = PivSession(yubikey.smart_card())


    # Check if YubiKey takes TDES or AES Management key
    """
    If there is no metadata support, then the YubiKey uses TDES.
    Otherwise we use the metadata to determine what key type to use.
    """
    try:
        mgmt_key_type = piv.get_management_key_metadata().key_type
    except NotSupportedError:
        print("NotSupportedError")
        mgmt_key_type = MANAGEMENT_KEY_TYPE.TDES

    # Authenticate with management key to perform key generation

    for i in range(3):
        try:
            # TODO: confirm hexadecimal and not decimal properties
            key = click.prompt("Please enter your Management Key", default=DEFAULT_MANAGEMENT_KEY.hex())
            piv.authenticate(mgmt_key_type, bytes.fromhex(key))
            #piv.authenticate(MANAGEMENT_KEY_TYPE.TDES, bytes.fromhex(key))
            #piv.authenticate(key_type,(DEFAULT_MANAGEMENT_KEY))
            break
        except:
            click.clear()
            click.secho("⛔ That does not look like the correct key!\n", fg="red")
            click.pause("Press any key to try again.")
            click.clear()
    if i == 2:
        click.clear()
        click.secho("🛑 No valid key provided. Exiting program...", fg="red")
        time.sleep(2) # Pause for 2 seconds
        click.clear()
        sys.exit()

    click.clear()

    # Generate a new key pair on the YubiKey
    click.echo(f"Generating {key_type.name} private key in slot {slot:X}...")
    try:
        pub_key = piv.generate_key(slot, key_type)
    except Exception as exc:
        print(exc)

    click.clear()

    # Prepare the subject:
    '''
    NOTE: For more details on CSR creation, please refer to:
        https://cryptography.io/en/latest/x509/reference/#x-509-csr-certificate-signing-request-builder-object
        https://cryptography.io/en/latest/x509/reference/#object-identifiers

    '''

    email = click.prompt("Please enter your email", default="alice.smith@contoso.com")
    commonName = click.prompt("Please enter your name", default="Alice Smith")
    orgName = click.prompt("Please enter your organization name", default="Users")
    domainName = click.prompt("Please enter your domain name", default="contoso")
    topDomain = click.prompt("Please enter your top domain name", default="com")
    # TODO: Solve *this* to better mimic the Entra ID / Azure AD expected certificate structure!
    # Define the Object Identifier (OID) for OtherName
    #oid_other_name = ObjectIdentifier('1.3.6.1.4.1.311.20.2.3')

    subject = x509.Name(
        [
            NameAttribute(oid.NameOID.EMAIL_ADDRESS, email),
            NameAttribute(oid.NameOID.COMMON_NAME, commonName),
            NameAttribute(oid.NameOID.ORGANIZATION_NAME, orgName),
            NameAttribute(oid.NameOID.DOMAIN_COMPONENT, domainName),
            NameAttribute(oid.NameOID.DOMAIN_COMPONENT, topDomain),
        ]
    )

    # Prepare the certificate
    builder = (
        CertificateSigningRequestBuilder()
        .subject_name(subject)
        # Some examples of extensions to add, many more are possible:
        .add_extension(
            BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            ExtendedKeyUsage(
                [
                    oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    oid.ExtendedKeyUsageOID.SMARTCARD_LOGON,
                ]
            ),
            critical=True,
        )
    .add_extension(
        SubjectAlternativeName(
            [
                RFC822Name(email),
                # TODO: Instead of 'RFC822Name(email' create Other Name > Principal Name = UPN

            ]
        ),
        critical=False,
    )

        )
    click.clear()


    # The user must input PIN
    for i in range(3):
        try:
            pin = click.prompt("Please enter your PIN", default=DEFAULT_PIN)
            piv.verify_pin(pin)
            break
        except:
            click.clear()
            click.secho("⛔ That does not look like the correct PIN!\n", fg="red")
            click.pause("Press any key to try again.")
            click.clear()
    if i == 2:
        click.clear()
        click.secho("🛑 No valid PIN provided. Exiting program...", fg="red")
        time.sleep(2) # Pause for 2 seconds
        click.clear()
        sys.exit()

    click.clear()


    # Sign the CSR
    csr = sign_csr_builder(piv, slot, pub_key, builder)
    pem = csr.public_bytes(serialization.Encoding.PEM)

    # Save CSR to file
    with open('csr.pem', 'wb') as f:
        f.write(pem)
    click.clear()

    # Attest the key
    click.echo(f"Attesting the created key in slot {slot:X}...")
    attestation = piv.attest_key(slot)
    attest_pem = attestation.public_bytes(serialization.Encoding.PEM)

    # Save Attestation certificate to file
    with open('attestation.pem', 'wb') as f:
        f.write(attest_pem)
    click.clear()

    # Export intermediate certificate from slot 9F
    intermediate = piv.get_certificate(slot.ATTESTATION)

    # Save Attestation certificate to file
    with open('intermediate.pem', 'wb') as f:
        f.write(intermediate.public_bytes(serialization.Encoding.PEM))
    click.clear()
    
    click.secho("✅ CSR and attestation certificates have been saved to current directory!", fg="green")

    # Return to menu system
    click.pause("\nPress any key to return to the main menu.")
    click.clear()

######################################################################################################################################
# VALIDATE ATTESTATION (OPTION 3)                                                                                                    #   
######################################################################################################################################

def validate_attestation():
    click.clear()    
    # Inform the user
    click.secho("   ________________________________________________________________________________________________   ", bg="blue")
    click.secho("  |                                                                                                |  ", bg="blue")
    click.secho("  |                                             INFO                                               |  ", bg="blue")
    click.secho("  | This option tests the authenticity of a certificate signing request (CSR) by verifying it's    |  ", bg="blue")
    click.secho("  | private key attestation against the YubiKey attestation certificate (exported from Slot 9F)    |  ", bg="blue")
    click.secho("  | and in turn verifying that certificate against the Yubico Root CA certificate.                 |  ", bg="blue")
    click.secho("  |                                                                                                |  ", bg="blue")
    click.secho("  | If the script returns 'SUCCESS' then you can be certain the CSR originates  with a key pair    |  ", bg="blue")
    click.secho("  | created on-board a YubiKey. If however the script returns 'FAIL' then the key pair may NOT     |  ", bg="blue")
    click.secho("  | have been generated on-board a YubiKey. In this case the CSR *should not* be signed by the CA. |  ", bg="blue")
    click.secho("  |                                                                                                |  ", bg="blue")          
    click.secho("  |________________________________________________________________________________________________|  ", bg="blue")
    click.secho("                                                                                                      ", bg="blue")

    # Prompt user to continue;)
    def continue_or_exit():
        if click.confirm("Do you want to continue?", default=True):
            click.clear()
        else:
            click.echo("Exiting the program...")
            # Perform cleanup or any necessary steps before exiting
            raise SystemExit

    continue_or_exit()
    click.clear()

   # Define function to verify signature
    def verify_signature(parent: x509.Certificate, child: x509.Certificate) -> None:
        parent.public_key().verify(
            child.signature,
            child.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child.signature_hash_algorithm
        )
    
    # Define function to display attested YubiKey attributes
    def get_yubikey_metadata(attestation_cert):
        """
        Extract and display YubiKey metadata from attestation certificate.
        
        Args:
            attestation_cert: x509 certificate containing YubiKey metadata
            
        Returns:
            None - prints metadata to console
        """
        firmware_version = serial_number = pin_policy = touch_policy = "Not Found"
        
        # Define form factor mapping
        form_factor_names = {
            b'\x00': "Unknown",
            b'\x01': "Keychain (USB-A)",
            b'\x02': "YubiKey Nano (USB-A)",
            b'\x03': "Keychain (USB-C)",
            b'\x04': "YubiKey Nano (USB-C)",
            b'\x05': "Keychain (Lightning + USB-C)",
            b'\x06': "YubiKey Bio MPE (USB-A)",
            b'\x07': "YubiKey Bio MPE (USB-C)"
        }

        # Initialize FIPS status as Non-FIPS by default
        fips_status = "false"
        
        for ext in attestation_cert.extensions:
            # Get Model / formfactor
            if ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.9":
                form_factor = form_factor_names.get(ext.value.value, "Unknown")
            
            # Get FIPS status
            elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.10":
                # If the OID is present, it's a FIPS device
                fips_status = "true"
            elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.7":
                # Get Serial Number
                ext_data = ext.value.value
                # Assuming the first two bytes are not part of the serial number, skip them
                serial_number = int(binascii.hexlify(ext_data[2:]), 16)
            
            elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.3":
                # Get Firmware Version
                ext_data = binascii.hexlify(ext.value.value).decode('utf-8')
                firmware_version = f"{int(ext_data[:2], 16)}.{int(ext_data[2:4], 16)}.{int(ext_data[4:6], 16)}"
            elif ext.oid.dotted_string == "1.3.6.1.4.1.41482.3.8":
                # Get PIN and Touch Policy
                ext_data = binascii.hexlify(ext.value.value).decode('utf-8')
                pin_policy = {"01": "never", "02": "once per session", "03": "always"}.get(ext_data[:2], "Unknown")
                touch_policy = {"01": "never", "02": "always", "03": "cached for 15s"}.get(ext_data[2:4], "Unknown")

        # Display the YubiKey metadata
        click.secho(f"✅ Model: {form_factor}", fg="green")
        click.secho(f"✅ FIPS certified: {fips_status}", fg="green")
        click.secho(f"✅ Serial Number: {serial_number}", fg="green")
        click.secho(f"✅ Firmware Version: {firmware_version}", fg="green")
        click.secho(f"✅ PIN Policy: {pin_policy}", fg="green")
        click.secho(f"✅ Touch Policy: {touch_policy}", fg="green")
  

    # Get file paths from user input or use default values
    csr_file = click.prompt("Please provide the path to the Certificate Signing Request (CSR)", default="csr.pem")
    click.clear()
    attestation_file = click.prompt("Please provide the path to the PIV Attestation Certificate", default="attestation.pem")
    click.clear()
    intermediate_file = click.prompt("Please provide the path to the Intermediate Certificate", default="intermediate.pem")
    click.clear()
    
    # This is the Yubico Root CA certificates. They will not be provided by the end-user
    ca_files = ["yubico-piv-ca-1.pem", "yubico-ca-1.pem"]
    ca_certs = []
    
    # Check if all CA certificates exist
    all_files_exist = all(os.path.isfile(f) for f in ca_files)
    
    if all_files_exist:
        # Look for the certificates on current working directory
        click.echo("Found Yubico CA certificates on current working directory...")
        click.echo("")
        click.pause()
        click.clear()
    else:
        # If we cannot find the files, download them!
        url1 = "https://developers.yubico.com/PKI/yubico-piv-ca-1.pem"  # Pre fw. 5.7.4 PIV root CA
        url2 = "https://developers.yubico.com/PKI/yubico-ca-1.pem"     # 5.7.4 and later PIV root CA (2025)
        
        urllib.request.urlretrieve(url1, ca_files[0])
        urllib.request.urlretrieve(url2, ca_files[1])
        
        click.echo("We successfully downloaded the Yubico CA certificates from yubico.com...")
        click.echo("")
        click.pause()
        click.clear()

    # Load certificate files and verify signatures
    try:
        with open(csr_file, 'rb') as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())
        with open(attestation_file, 'rb') as f:
            attestation_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(intermediate_file, 'rb') as f:
            intermediate_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
        # Load all CA certificates
        for ca_file in ca_files:
            with open(ca_file, 'rb') as f:
                ca_certs.append(x509.load_pem_x509_certificate(f.read(), default_backend()))

        # Check if public keys match and display the results
        click.echo("-------------------")
        click.echo("VALIDATION RESULTS:")
        click.echo("===================")
        # Ensure the intermediate cert is signed by at least one of the root CAs
        valid_root = False
        for ca_cert in ca_certs:
            try:
                verify_signature(ca_cert, intermediate_cert)
                valid_root = True
                break  # Stop checking once one valid CA is found
            except Exception:
                pass  # Continue to the next CA if the first check fails

        if not valid_root:
            click.secho("💀 Intermediate certificate validation failed against all known Yubico root CAs.", fg="red")
            sys.exit(1)

        verify_signature(intermediate_cert, attestation_cert)
        
        if csr.public_key().public_numbers() == attestation_cert.public_key().public_numbers():
            click.secho("✅ Public keys match", fg="green")
        else:
            click.secho("💀 CSR public key does not match attestation public key", fg="red")
            sys.exit(1)
        click.secho("✅ Signature validation succeeded.", fg="green")
        
        # Display attested YubiKey attributes
        get_yubikey_metadata(attestation_cert)

    except FileNotFoundError:
        click.secho("⛔ One or more of the requested files were not found.", fg="red")

    except Exception:
        click.secho("⛔ CA path validation failed.", fg="red")

    # Return to menu system
    click.pause("\nPress any key to return to the main menu.")
    click.clear()


######################################################################################################################################
# IMPORT SIGNED CERTIFICATE (OPTION 4)                                                                                               #   
######################################################################################################################################

def import_certificate():
    click.clear()

    # Inform the user
    click.secho("   ________________________________________________________________________________________________   ", bg="blue")
    click.secho("  |                                                                                                |  ", bg="blue")
    click.secho("  |                                             INFO                                               |  ", bg="blue")
    click.secho("  | This option takes in a user provided card Management Key and then imports a *signed* (note!)   |  ", bg="blue")
    click.secho("  | certificate into the default PIV authentication slot (9A). Once imported the user is able to   |  ", bg="blue")
    click.secho("  | use the YubiKey for Certificate-Based Authentication (CBA).                                    |  ", bg="blue")
    click.secho("  |                                                                                                |  ", bg="blue")      
    click.secho("  |________________________________________________________________________________________________|  ", bg="blue")
    click.secho("                                                                                                      ", bg="blue")

    # Prompt user to continue
    def continue_or_exit():
        if click.confirm("Do you want to continue?", default=True):
            click.clear()
        else:
            click.echo("Exiting the program...")
            # Perform cleanup or any necessary steps before exiting
            raise SystemExit

    continue_or_exit()
    click.clear()

    # Connect to a YubiKey
    yubikey = s.single()

    # Establish a PIV session
    piv = PivSession(yubikey.smart_card())

    # Check if YubiKey takes TDES or AES Management key
    """
    If there is no metadata support, then the YubiKey uses TDES.
    Otherwise we use the metadata to determine what key type to use.
    """
    try:
        mgmt_key_type = piv.get_management_key_metadata().key_type
    except NotSupportedError:
        print("NotSupportedError")
        mgmt_key_type = MANAGEMENT_KEY_TYPE.TDES
    
    # Authenticate with management key in order to support certificate import
    for i in range(3):
        try:
            # TODO: confirm hexadecimal and not decimal properties
            key = click.prompt("Please enter your Management Key", default=DEFAULT_MANAGEMENT_KEY.hex())
            piv.authenticate(mgmt_key_type, bytes.fromhex(key))
            break
        except:
            click.clear()
            click.secho("⛔ That does not look like the correct key!\n", fg="red")
            click.pause("Press any key to try again.")
            click.clear()
    if i == 2:
        click.clear()
        click.secho("🛑 No valid key provided. Exiting program...", fg="red")
        time.sleep(2) # Pause for 2 seconds
        click.clear()
        sys.exit()

    click.clear()

    # Prompt user to supply signed CSR
    signed_file = click.prompt("Please provide the path to the *signed* user certificate", default="signed.crt")
    click.clear()
    try:
        with open(signed_file, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            piv.put_certificate(SLOT.AUTHENTICATION, cert)
            # Only show success message if no exception occurred
            click.secho(f"✅ Certificate successfully imported to slot {slot:X}.", fg="green")
    except Exception as e:
        click.secho(f"⛔ An error occurred while loading the certificate: {str(e)}", fg="red")

    # Exit program on user acknowledgement
    click.pause("\nPress any key to exit this program!")
    click.clear()


#def cleanup():
#    """Perform cleanup operations before exiting"""
#    try:
#        piv.disconnect() # TODO: fix this!
#    except Exception as e:
#        logging.error(f"Error during cleanup: {str(e)}")

def quit_program():
    click.echo("Quitting the program...")
    #cleanup()
    click.clear()
    sys.exit()


######################################################################################################################################
# THIS IS OUR MAIN MENU SYSTEM                                                                                                       #   
######################################################################################################################################

menu = {
    "1": "Configure YubiKey",
    "2": "Create a CSR",
    "3": "Validate attestation",
    "4": "Import certificate",
    "5": "Quit program"
}


while True:
    options = menu.keys()

    # Inform the user about the purpose of the script and its options
    click.secho("   ________________________________________________________________________________________________   ", bg="green")
    click.secho("  |                                                                                                |  ", bg="green")
    click.secho("  |                                            WELCOME                                             |  ", bg="green")
    click.secho("  | This script is designed to perform administrative tasks related to YubiKey PIV lifecycle.      |  ", bg="green")
    click.secho("  |                                                                                                |  ", bg="green")
    click.secho("  | OPTION 1 resets the YubiKey PIV applet and then sets a new Management Key, a new PUK, & PIN.   |  ", bg="green")
    click.secho("  | The script offers to randomize the Management Key as well as the PUK, but the PIN must be set  |  ", bg="green")
    click.secho("  | by the user. PUK and PIN selection must not be trivial (easy to guess).                        |  ", bg="green")
    click.secho("  |                                                                                                |  ", bg="green")
    click.secho("  | OPTION 2 generates a new key pair in the PIV Authentication slot (9A) to support CBA           |  ", bg="green")   
    click.secho("  | Certificate-Based Authentication. A Certificate Signing Request (CSR) is then generated based  |  ", bg="green")                                                                                                 
    click.secho("  | on end-user input. The script outputs the necessary files to support certificate issuance.     |  ", bg="green")
    click.secho("  |                                                                                                |  ", bg="green")         
    click.secho("  | OPTION 3 validates the CSR and auxiliary certificates created in option 2 by checking the      |  ", bg="green")
    click.secho("  | Attestation Certificate and the necessary CA signatures. This option is intended to be run by  |  ", bg="green")
    click.secho("  | an administrator, prior to signing the CSR using a Certificate Authority (out of scope).       |  ", bg="green")
    click.secho("  |                                                                                                |  ", bg="green")
    click.secho("  | OPTION 4 imports a signed certificate to the PIV Authentication slot (9A), thus completing the |  ", bg="green")
    click.secho("  | Issuance process. This step is intended to be performed by the end-user.                       |  ", bg="green")
    click.secho("  |                                                                                                |  ", bg="green")
    click.secho("  |________________________________________________________________________________________________|  ", bg="green")
    click.secho("                                                                                                      ", bg="green")
    
    click.pause("\nPress any key to continue.")
    click.clear()
    click.secho("MAIN MENU:")
    click.secho("==========\n")

    for option in options:
        print(option + ". " + menu[option])
    selection = input("\nPlease select an option: ")
    if selection == "1":
        configure_yubikey()
    elif selection == "2":
        create_csr()
    elif selection == "3":
        validate_attestation()
    elif selection == "4":
        import_certificate()
    elif selection == "5":
        quit_program()
    else:
        click.clear()
        click.secho("⛔ Invalid selection, please try again!", fg="red")
        click.pause("\nPress any key to return to the main menu.")
        click.clear()
