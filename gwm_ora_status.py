#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GWM ORA 03 API Data Retrieval Script
This script logs into the Great Wall Motor (GWM) EU gateway,
retrieves the user's vehicles, and prints telemetry:
1. SOC (Batterieladestand)
2. Reichweite (Range)
3. Kilometerstand (Odometer)
4. Lade-Status (Charging status)

It handles the mutual TLS (mTLS) decryption automatically.
Supports token caching, automatic token refresh, untrusted device verification,
and automatic email verification code extraction via IMAP (Gmail, Outlook, etc.).
"""

import os
import sys
import ctypes
from ctypes.util import find_library
import ssl

def load_openssl_providers():
    libcrypto_path = find_library('crypto')
    libcrypto = None
    if libcrypto_path:
        try:
            libcrypto = ctypes.CDLL(libcrypto_path)
        except Exception:
            pass
            
    if not libcrypto:
        for name in ['libcrypto.so.3', 'libcrypto.so.1.1', 'libcrypto.so', 'libcrypto.so.3.0']:
            try:
                libcrypto = ctypes.CDLL(name)
                break
            except Exception:
                pass
                
    if not libcrypto:
        try:
            libcrypto = ctypes.CDLL(None)
        except Exception:
            return False

    try:
        OSSL_PROVIDER_load = libcrypto.OSSL_PROVIDER_load
        OSSL_PROVIDER_load.argtypes = (ctypes.c_void_p, ctypes.c_char_p)
        OSSL_PROVIDER_load.restype = ctypes.c_void_p
        prov_default = OSSL_PROVIDER_load(None, b"default")
        prov_legacy = OSSL_PROVIDER_load(None, b"legacy")
        return bool(prov_default and prov_legacy)
    except Exception:
        return False

load_openssl_providers()

import uuid
import json
import base64
import math
import random
import requests
from requests.adapters import HTTPAdapter

orig_init_poolmanager = HTTPAdapter.init_poolmanager

def custom_init_poolmanager(self, *args, **kwargs):
    if 'ssl_context' not in kwargs:
        context = ssl.create_default_context()
        try:
            context.set_ciphers('DEFAULT@SECLEVEL=0')
        except Exception:
            pass
        kwargs['ssl_context'] = context
    else:
        context = kwargs['ssl_context']
        try:
            context.set_ciphers('DEFAULT@SECLEVEL=0')
        except Exception:
            pass
    return orig_init_poolmanager(self, *args, **kwargs)

HTTPAdapter.init_poolmanager = custom_init_poolmanager

script_dir = os.path.dirname(os.path.abspath(__file__))
import imaplib
import email
import re
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

CONFIG_PATH = os.path.join(script_dir, "gwm_config.json")

# Embedded GWM General Certificate (PEM format)
GWM_GENERAL_CER = """-----BEGIN CERTIFICATE-----
MIIEPTCCAyWgAwIBAgIULWrBpHk0yzJYVC9S6kiODBQdcwQwDQYJKoZIhvcNAQEL
BQAwgZgxHjAcBgNVBAMMFUlPViBBUFAgR2VuZXJhbCBTdWJDQTEfMB0GA1UECwwW
RUUgU3lzdGVtIERlc2lnbiBEZXB0LjEjMCEGA1UECgwaR3JlYXQgV2FsbCBNb3Rv
ciBDby4sIEx0ZC4xCzAJBgNVBAYTAkNOMSMwIQYJKoZIhvcNAQkBDBRjeWJlcnNl
Y3VyaXR5QGd3bS5jbjAeFw0yMjAxMDUwMTUyMDRaFw0yNzAxMDQwMTUyMDRaMIG7
MR0wGwYDVQQDDBRMR1dHV00tQUQtRVUtR0VORVJBTDEfMB0GA1UECwwWRUUgU3lz
dGVtIERlc2lnbiBEZXB0LjEjMCEGA1UECgwaR3JlYXQgV2FsbCBNb3RvciBDby4s
IEx0ZC4xCzAJBgNVBAYTAkRFMRQwEgYDVQQIDAtPcGVyYXRpb25hbDEMMAoGA1UE
BwwDQVBQMSMwIQYJKoZIhvcNAQkBDBRjeWJlcnNlY3VyaXR5QGd3bS5jbjCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK9g98IIv6rb06r3PTZOQTwgqImQ
qgXAggHUZF4JM8E9Wl3u5E3oMoj5IWfvo/71NXpyq8pRy/w29whxHbWWL4HvSQDf
KHhSX0ahnMqXBuy+xBdtWJ/kjxRVZtdlwdkxPw9gHZ/KkN7hJbeaSYq/4Bl+JCzl
NdS7QA1+zfE97o6jW5rhLcffd5sMDpjSAtOeYLx7CQ+Nl8RSZywG7rKu7rK1GG3J
o5rl9bZ/1CVLFZs16BYqZoTav6DlxtfCeVHyqBbXbBWJ5Y/xnhr/uj1IBV/7mFbQ
cLE/+IKOR0dxZLE1sNlwtUGCRL4AnF++Uk7U9TTxCYiZjdsxLzuKR79hvM8CAwEA
AaNaMFgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBsAwHwYDVR0jBBgwFoAUzc1fwwqk
16jA0D4GbfiLGFHYbtgwHQYDVR0OBBYEFPBDYUMdBWtUSMyfhMK1IuQQdvPkMA0G
CSqGSIb3DQEBCwUAA4IBAQCCAlwmxfMSjp+R1rkVTh9PfRXZSVvg/WSpDMJwz7lt
SoVKEk20/L80gijWBJBcPS1N0AoQWM2FtPn3r2ojj7GYf2i5nr156hHgxrPoAbAV
pGTWSOyebTHDClC+dL5wSXxeP9kuVAptTbfLtCOzSrcoTSebqaJKYzOoGaROeXXa
FdT25rXknCTJqGDdmv4062e3wv/SsU1nDuvgvEPVvVyLyx7kDkyv1DIt/wo9vFXH
WOwb1ldJZS57N1W1TqORQd6H9HuxmMOATmaM+B6b1NNI4l+Cge+15pZmMDCWc9c3
2/wjata19r5A09DM1NAIhGLGWZvEbAkEsqOkgeMRpv9d
-----END CERTIFICATE-----"""

# Embedded GWM General Transformed Key (Base64 format)
GWM_GENERAL_KEY_B64 = "MIICHwIBAAKCAQEAr2D3wgi/qtvTqvc9Nk5BPCCoiZCqBcCCAdRkXgkzwT1aXe7kTegyiPkhZ++j/vU1enKrylHL/Db3CHEdtZYvge9JAN8oeFJfRqGcypcG7L7EF21Yn+SPFFVm12XB2TE/D2Adn8qQ3uElt5pJir/gGX4kLOU11LtADX7N8T3ujqNbmuEtx993mwwOmNIC055gvHsJD42XxFJnLAbusq7usrUYbcmjmuX1tn/UJUsVmzXoFipmhNq/oOXG18J5UfKoFtdsFYnlj/GeGv+6PUgFX/uYVtBwsT/4go5HR3FksTWw2XC1QYJEvgCcX75STtT1NPEJiJmN2zEvO4pHv2G8zwIBAQKCAQEApv0XGYjck2la7MyverEhPTPUyio718Gw5OLzQj7xFvGhtdL0PjcImIDphbdvEWeUFYTHF+73B0ocOkvFCjLfwcm9NBuzXiRB1mti972tAfDC5qIaf4Vo0lR6aey3mr4iq6iB+ynwtPDEhPGWf13f7gVOkgacMVQXjtlv8Rec0qDiE4QOuRCwnPNffXUrnVkCQ7yed1WAbZ98OKAB2zyQKyJkHyYAFW6JluiUBZDvGK6WFMI49KZLNl8gBl/22/RCn3+xwKYqysyd9PMjakk88iIl+fkDtVQAk760vflMR1IFXM1xsHh/56aBlTVzKxSMIMvFmQCmRvBphY28/Q76BgIBAQIBAQIBAQIBAQIBAQ=="

# Embedded GWM Root CA chain
GWM_ROOT_PEM = """-----BEGIN CERTIFICATE-----
MIIEVjCCAz6gAwIBAgIUK3xBGIzHcMyho88Vad9uuLKwLOcwDQYJKoZIhvcNAQEL
BQAwgY4xFDASBgNVBAMMC0dXTSBSb290IENBMR8wHQYDVQQLDBZFRSBTeXN0ZW0g
RGVzaWduIERlcHQuMSMwIQYDVQQKDBpHcmVhdCBXYWxsIE1vdG9yIENvLiwgTHRk
LjEjMCEGCSqGSIb3DQEJARMUY3liZXJzZWN1cml0eUBnd20uY24xCzAJBgNVBAYM
AkNOMCAXDTE5MTAyMzA2MTYzM1oYDzIxMTkwOTI5MDYxNjMzWjCBjjEUMBIGA1UE
AwwLR1dNIFJvb3QgQ0ExHzAdBgNVBAsMFkVFIFN5c3RlbSBEZXNpZ24gRGVwdC4x
IzAhBgNVBAoMGkdyZWF0IFdhbGwgTW90b3IgQ28uLCBMdGQuMSMwIQYJKoZIhvcN
AQkBExRjeWJlcnNlY3VyaXR5QGd3bS5jbjELMAkGA1UEBgwCQ04wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDU1qVkRC+3U7+UcXfD6OnFNZBzvrJGvjb
OMgJGWWTTHMO684wGl793+q4dxGlu6BY6fYzhbtG4rsSSQJKVjN3mF7wfeGrlYWZ
iFqGsaOWN8EpywE5k2QXWqtxwuhShrVUp4tt/ML2J7vnZmkMHKk4/QgVY2Q8iOXL
IEup6Pq+hR0gglSTE+mZZVDV1sR4z/l0lXsdKPJoQeXmCL25K/ql7t0Nnk1EtQf2
pCXY+/3DnSG+bnD+mMjzIM5I/xx2dSoEHx/IbI+65nZ8DA4GKPCmMvtjOgsb40Bw
DukwPrEnUZeloY6qWooxGFxFNc/hMdjCXPT8b1TjKIfyTVDRoT+lAgMBAAGjgacw
gaQwHQYDVR0OBBYEFFbiQZYv17vgPuXjzWnru6bqMBMbMAwGA1UdEwQFMAMBAf8w
CwYDVR0PBAQDAgEGMGgGA1UdHwRhMF8wXaBboFmGV2h0dHA6Ly8xMC4yNTUuNTIu
MTIyOjgwODAvb2ZmbGluZUNBL3B1YmxpYy9pdHJ1c2NybD9DQT03MTk5MzRmODM3
ZWNlNzFmNGU4YTBmN2RiZjJlNzUwODANBgkqhkiG9w0BAQsFAAOCAQEAc8goqBF2
TRkWsTUBiBpXlfWqcc1jbwQqM8iEULj3dwjhiXcBQhaVdRp4Ry0r7X1K49zwowHz
6yZREzbMuHFFjcaRQfRsimNMOAJ7MeuNUSdRDQypPMa1XN4Seo0SXerjW3PhUxUp
/O0v72ytfneKM6lHGXW+SmVixwNSeZip3Emq/TGzFEcMG7YxrY7NWoNlv1X2NOhz
r9XGwGZyxdApJZV3Vbj5Wea/H8Hkf8q/cMPsWvlnpze4RNvNZQdke5Kuem/v09Iq
OPZ2ES2oncmaz22BImHMbueY3BXvTWGYbpqolHv1oE+3RLeRdY5z9KLMRjQn4T8J
hmldk0Sdt4OwJA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEDjCCAvagAwIBAgIUXfkkvyEKMB2xbS0KoRKdaYIZoLkwDQYJKoZIhvcNAQEL
BQAwgY4xFDASBgNVBAMMC0dXTSBSb290IENBMR8wHQYDVQQLDBZFRSBTeXN0ZW0g
RGVzaWduIERlcHQuMSMwIQYDVQQKDBpHcmVhdCBXYWxsIE1vdG9yIENvLiwgTHRk
LjEjMCEGCSqGSIb3DQEJARMUY3liZXJzZWN1cml0eUBnd20uY24xCzAJBgNVBAYM
AkNOMCAXDTIxMDcxNTA3MTczNFoYDzIxMjEwNjIxMDcxNzM0WjCBkTELMAkGA1UE
BgwCREUxIzAhBgkqhkiG9w0BCQEMFGN5YmVyc2VjdXJpdHlAZ3dtLmNuMSMwIQYD
VQQKDBpHcmVhdCBXYWxsIE1vdG9yIENvLiwgTHRkLjEgMB4GA1UECwwXRUUgU3lz
dGVtIERlc2lnbiBEZXB0LiAxFjAUBgNVBAMMDUlPViBBUFAgU3ViQ0EwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4jCH1GYXnge22BXFai+CGZiaVmxg6
+WYvyTmDw+FqXyB8DCccHv0kUALTKxlKDF7T5AbNWTJx4SqX3KHW2I2nFUAZZx1Q
aS9+2zFGVhIF6Vppo29yGdLGpMfG1NyBjvVU6ZjCtezDUqKguf4Si6hy80OF8i2l
6CevHU5B6Moqrca51pJLW6wY7DHiswA0I2eLy9EQ5ThvUcOjmMQVkrFQFccXtlFQ
V0nIspi9lea3zWHaxYS7KA2dfdyS7+EMuWL9uamJxywwN0ZuvF2kSVOUk1KWVpaT
iawwfAXYHWhHeL3nCxwxYJ+UIWN8IxbHO11Ey6IGN48FtIZyruTvMdWHAgMBAAGj
XTBbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMB8GA1UdIwQYMBaAFFbiQZYv
17vgPuXjzWnru6bqMBMbMB0GA1UdDgQWBBR1NqHawRRHlfE9+KzySteRwHHxbDAN
BgkqhkiG9w0BAQsFAAOCAQEAAtitEtpDPIhHD2mg82vQkA7l0LjQ9brEOCbjBCkd
7gYwkAGMxF8hAmk+bAai8LRIldBKp+XXXumU975UUAC6wP7fBesNWVpQkHWDGHLZ
aIiOmV6NPk5lsgGO4oQi8/2LE7VSW4MEDtlEfK/lnADpou9QtzNeX7+ykX9/aXDF
WRL8mbn3btXqofZ6FyScPYstyPubjc7LSlkCe/phLUkDcMIkNllasF28VOf/PRax
EvhwpISY4lfRCAFYwVYVixkKbzcwjDujw+hjeuqYBtZ4EfdXnW1L7bLIZMdI1FhP
zDIZAroHKwg6pRMFzOBaT0X7pBxffxMRu1HoOhrphk3OAg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEGzCCAwOgAwIBAgIUTliAbg0//nqet/iiPQ8GYTmeiKEwDQYJKoZIhvcNAQEF
BQAwgY4xFDASBgNVBAMMC0dXTSBSb290IENBMR8wHQYDVQQLDBZFRSBTeXN0ZW0g
RGVzaWduIERlcHQuMSMwIQYDVQQKDBpHcmVhdCBXYWxsIE1vdG9yIENvLiwgTHRk
LjEjMCEGCSqGSIb3DQEJARMUY3liZXJzZWN1cml0eUBnd20uY24xCzAJBgNVBAYM
AkNOMCAXDTIxMDEyNTA4MTQwNFoYDzIxMjAwOTI1MDgxNDA0WjCBmDEeMBwGA1UE
AwwVSU9WIEFQUCBHZW5lcmFsIFN1YkNBMR8wHQYDVQQLDBZFRSBTeXN0ZW0gRGVz
aWduIERlcHQuMSMwIQYDVQQKDBpHcmVhdCBXYWxsIE1vdG9yIENvLiwgTHRkLjEL
MAkGA1UEBhMCQ04xIzAhBgkqhkiG9w0BCQEMFGN5YmVyc2VjdXJpdHlAZ3dtLmNu
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvklPTH/HHtreE9GbrmTj
4moHXPpOTA6hVl3kajVK8E5o9SLIDgHATA4KUAcTYjxWaRSy9zRThpbNSBGApUw0
BCeV8d/z0ON2kK6ZJHEc0VLJyg5eFPRpk8fPzMDY6BjttOWbyVQM1HNkxrbhT4HK
w+ia9BMw5cK98Nl2Yb/GFGpD+BCmjkg7n5xEg7dVRoEdBJKjer8DLv2Zx22I2R7x
etpu8BrGX4rNBK91z2bT/363Pem3VVND82hbv3HAsE7Dk/3KLJi9Xrpo63Ot+E4I
XB0aFpR9TEs0mSvAI5Dnju3aTzMtGdKBl3xZwE8AOq01jp8JPggEN8DAxCzwMQnp
0wIDAQABo2MwYTAdBgNVHQ4EFgQUzc1fwwqk16jA0D4GbfiLGFHYbtgwHwYDVR0j
BBgwFoAUVuJBli/Xu+A+5ePNaeu7puowExswDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBAHBL6UqZpESiWIN+ygsFE/8z
7tkVxgtnrohHgtsVt8NdZohf62/yOMP6eAW32GKrwHDGPSKFcT6wdsRBUBjh6HDn
qGb5pWbGtYV4H5Z6ePa2qFWkUphd+ZYyyPUk6W9+4PsZpbC/4ybxHRxPAMW1r0Gc
mYme6uwVFpTu0kcUXno7xZXxUXWlXzZSWl9Yq57yXJ5ansQsf5sZFhQCmEPOFMEX
pJpt3VMRhoSn9HzSIlTBsjM5kQIErdczYeIeY/BsKI2gUjCNAvDLZ/Rcz09X2bQS
zR3ZPcShmJT8Z78BEQUXoJbvCSTqwq2VX0fFY50RcAidJ76HjDTDr59aVTiXpQs=
-----END CERTIFICATE-----"""

def untransform(number):
    bits = number.bit_length()
    five_bit_number_count = bits // 5
    if bits % 5 != 0:
        five_bit_number_count += 1
    
    five_bit_numbers = [0] * five_bit_number_count
    for i in range(1, five_bit_number_count + 1):
        five_bit_numbers[-i] = int(number & 0x1f)
        number >>= 5
        
    res_number = five_bit_numbers[0]
    for i in range(1, five_bit_number_count):
        res_number <<= 5
        val = (five_bit_numbers[i] & 0xf8) + ((five_bit_numbers[i] + 3) & 7)
        res_number |= val
        
    return res_number

def parse_der_length(data, offset):
    b = data[offset]
    offset += 1
    if b < 0x80:
        return b, offset
    else:
        num_bytes = b & 0x7f
        length = 0
        for _ in range(num_bytes):
            length = (length << 8) | data[offset]
            offset += 1
        return length, offset

def parse_der_integer(data, offset):
    assert data[offset] == 0x02, f"Expected integer tag 0x02, got 0x{data[offset]:02x}"
    offset += 1
    length, offset = parse_der_length(data, offset)
    val_bytes = data[offset : offset + length]
    value = int.from_bytes(val_bytes, byteorder='big', signed=True)
    offset += length
    return value, offset

def parse_gwm_key(key_bytes):
    assert key_bytes[0] == 0x30
    offset = 1
    seq_len, offset = parse_der_length(key_bytes, offset)
    
    version, offset = parse_der_integer(key_bytes, offset)
    n, offset = parse_der_integer(key_bytes, offset)
    dummy_e, offset = parse_der_integer(key_bytes, offset)
    transformed_d, offset = parse_der_integer(key_bytes, offset)
    
    return n, transformed_d

def recover_pq(n, e, d):
    k = d * e - 1
    if k % 2 == 0:
        r = k
        t = 0
        while r % 2 == 0:
            r //= 2
            t += 1
        
        success = False
        y = 0
        for _ in range(100):
            g = random.randint(2, n - 1)
            y = pow(g, r, n)
            
            if y == 1 or y == n - 1:
                continue
                
            for _ in range(1, t):
                x = pow(y, 2, n)
                if x == 1:
                    success = True
                    break
                if x == n - 1:
                    break
                y = x
            else:
                x = pow(y, 2, n)
                if x == 1:
                    success = True
                    
            if success:
                break
                
        if success:
            p = math.gcd(y - 1, n)
            q = n // p
            if p < q:
                p, q = q, p
            return p, q
            
    raise Exception("Cannot compute P and Q")

def setup_client_key(cert_pem, key_b64):
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    e = cert.public_key().public_numbers().e

    key_bytes = base64.b64decode(key_b64)
    n, transformed_d = parse_gwm_key(key_bytes)
    d = untransform(transformed_d)
    
    p, q = recover_pq(n, e, d)
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)
    
    public_numbers = rsa.RSAPublicNumbers(e, n)
    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=public_numbers
    )
    private_key = private_numbers.private_key()
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

def save_config(config_data):
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config_data, f, indent=2)
    except Exception as e:
        if "--json" not in sys.argv:
            print(f"[-] Fehler beim Speichern der Konfiguration: {e}")

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return None

def refresh_token(config, headers_h5):
    refresh_url = "https://eu-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/refreshToken"
    refresh_body = {
        "accessToken": config["accessToken"],
        "refreshToken": config["refreshToken"],
        "deviceId": config["deviceId"]
    }
    try:
        response = requests.post(refresh_url, json=refresh_body, headers=headers_h5)
        if response.status_code == 200:
            resp_data = response.json()
            if resp_data.get("code") == "000000":
                config["accessToken"] = resp_data["data"]["accessToken"]
                config["refreshToken"] = resp_data["data"]["refreshToken"]
                save_config(config)
                return True
    except Exception:
        pass
    return False

def get_verification_code_via_imap(imap_config):
    """
    Connects to the IMAP server to retrieve the newest 4-digit code from GWM.
    """
    server = imap_config.get("server")
    user = imap_config.get("user")
    password = imap_config.get("password")
    
    if not server or not user or not password:
        return None
        
    try:
        # Wait a few seconds for the email to arrive
        time.sleep(10)
        
        # Connect to IMAP server
        mail = imaplib.IMAP4_SSL(server)
        mail.login(user, password)
        mail.select("inbox")
        
        # Search for GWM emails (both read and unread, to handle auto-read by other devices)
        status, messages = mail.search(None, '(SUBJECT "GWM")')
        if not messages[0]:
            status, messages = mail.search(None, '(FROM "gwm.cn")')
            
        if messages[0]:
            mail_ids = messages[0].split()
            # Loop from newest to oldest
            for latest_id in reversed(mail_ids):
                status, data = mail.fetch(latest_id, '(RFC822)')
                
                for response_part in data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        # Check Date header to ensure we only look at recent emails (within last 10 minutes)
                        msg_date_str = msg.get("Date")
                        if msg_date_str:
                            try:
                                import datetime
                                from email.utils import parsedate_to_datetime
                                msg_date = parsedate_to_datetime(msg_date_str)
                                now = datetime.datetime.now(datetime.timezone.utc)
                                diff = now - msg_date
                                # If the email is older than 10 minutes, skip it to prevent using outdated codes
                                if abs(diff.total_seconds()) > 600:
                                    continue
                            except Exception:
                                pass
                        
                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                    break
                            if not body:
                                # Fallback to HTML body
                                for part in msg.walk():
                                    if part.get_content_type() == "text/html":
                                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                        break
                        else:
                            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                            
                        # If body is still empty, convert the whole message to string as last resort
                        if not body:
                            try:
                                body = msg.as_string()
                            except Exception:
                                pass
                                
                        # Find 4-digit verification code with context keywords to avoid matching years (like 2026)
                        match = re.search(r'(?:code|verification|bestätigung|bestaetigung|verifizierung|safety)[^\d]{0,50}\b(\d{4})\b', body, re.IGNORECASE)
                        if not match:
                            # Fallback: look for any 4-digit number
                            match = re.search(r'\b(\d{4})\b', body)
                            
                        if match:
                            code = match.group(1)
                            # Mark email as read
                            mail.store(latest_id, '+FLAGS', '\\Seen')
                            mail.logout()
                            return code
        mail.logout()
    except Exception:
        pass
    return None

def perform_fresh_login(config, json_mode):
    if not config:
        # Prompt for credentials interactively (only if not json_mode)
        if json_mode:
            print(json.dumps({"error": "No config file found. Please run interactively first."}))
            return None
        
        default_user = "dein_email@domain.com"
        username = input(f"Benutzername/Email [{default_user}]: ").strip()
        if not username:
            username = default_user
            
        password = input("Passwort: ").strip()
        if not password:
            print("Fehler: Passwort darf nicht leer sein.")
            return None

        default_country = "DE"
        country = input(f"Landescode (z.B. DE, GB, AT, CH) [{default_country}]: ").strip().upper()
        if not country:
            country = default_country

        device_id = uuid.uuid4().hex
        config = {
            "country": country,
            "username": username,
            "password": password,
            "deviceId": device_id,
            "accessToken": "",
            "refreshToken": ""
        }
        save_config(config)
    else:
        username = config.get("username")
        password = config.get("password")
        country = config.get("country", "DE")
        device_id = config.get("deviceId")
        if not device_id:
            device_id = uuid.uuid4().hex
            config["deviceId"] = device_id
            save_config(config)

    headers_h5 = {
        "rs": "2",
        "terminal": "GW_APP_ORA",
        "brand": "3",
        "language": "de",
        "systemType": "1",
        "cver": "",
        "country": country
    }

    login_body = {
        "account": username,
        "agreement": [1, 2, 23],
        "appType": 0,
        "country": country,
        "deviceId": device_id,
        "isEncrypt": False,
        "model": "ora2mqtt",
        "pushToken": "",
        "type": 1,
        "password": password
    }
    
    if not json_mode:
        print("\n[+] Versuche Anmeldung am GWM H5-Gateway...")
    login_url = "https://eu-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/loginAccount"
    
    try:
        response = requests.post(login_url, json=login_body, headers=headers_h5)
        if response.status_code != 200:
            if not json_mode:
                print(f"[-] HTTP Fehler bei der Anmeldung: {response.status_code}")
            return None
            
        resp_data = response.json()
        code = resp_data.get("code")
        desc = resp_data.get("description", "")
        
        # Untrusted device flow
        if code == "110641":
            if not json_mode:
                print("\n[!] Neues Gerät erkannt. Fordere Verifizierungscode an...")
            sms_code_url = "https://eu-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/getSMSCode"
            sms_code_body = {
                "email": username,
                "scenario": 0,
                "type": 3
            }
            sms_code_resp = requests.post(sms_code_url, json=sms_code_body, headers=headers_h5)
            if sms_code_resp.status_code != 200:
                if not json_mode:
                    print("[-] Fehler bei Anforderung des Verifizierungscodes.")
                return None
                
            sms_code = None
            if config.get("imap"):
                if not json_mode:
                    print("[+] Lese Verifizierungscode automatisch aus E-Mail-Postfach...")
                for attempt in range(3):
                    sms_code = get_verification_code_via_imap(config["imap"])
                    if sms_code:
                        break
                    if not json_mode:
                        print(f"[+] Warte auf E-Mail (Versuch {attempt+1}/3)...")
                    time.sleep(10)
                    
            if not sms_code:
                if json_mode:
                    print(json.dumps({"error": "Device untrusted and no IMAP config found for automation."}))
                    return None
                sms_code = input("Bitte den 4-stelligen Code aus der E-Mail eingeben: ").strip()
                
            if not sms_code:
                if not json_mode:
                    print("Fehler: Verifizierungscode darf nicht leer sein.")
                return None
                
            sms_body = {
                "agreement": [1, 2, 23],
                "appType": 0,
                "country": country,
                "deviceId": device_id,
                "email": username,
                "model": "ora2mqtt",
                "pushToken": "",
                "smsCode": sms_code
            }
            sms_url = "https://eu-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/loginWithSMS"
            response = requests.post(sms_url, json=sms_body, headers=headers_h5)
            if response.status_code != 200:
                if not json_mode:
                    print(f"[-] HTTP Fehler bei der Verifizierung: {response.status_code}")
                return None
            resp_data = response.json()
            code = resp_data.get("code")
            desc = resp_data.get("description", "")
            
        if code != "000000":
            if not json_mode:
                print(f"[-] Anmeldung/Verifizierung fehlgeschlagen (Code {code}): {desc}")
                if code == "308008":
                    print("[!] HINWEIS: Dieses Konto ist wegen zu vieler Fehlversuche für 2 Stunden gesperrt.")
            else:
                print(json.dumps({"error": f"Login failed: {desc} (code {code})"}))
            return None
            
        access_token = resp_data["data"]["accessToken"]
        refresh_token_val = resp_data["data"]["refreshToken"]
        if not json_mode:
            print("[+] Anmeldung erfolgreich! Access-Token erhalten.")
        
        # Save configuration
        config["accessToken"] = access_token
        config["refreshToken"] = refresh_token_val
        save_config(config)
        return config
        
    except Exception as e:
        if not json_mode:
            print(f"[-] Verbindungsfehler: {e}")
        else:
            print(json.dumps({"error": str(e)}))
        return None

def main():
    json_mode = "--json" in sys.argv
    
    if not json_mode:
        print("=========================================================")
        print(" GWM ORA 03 Telemetry Status Retrieval Tool")
        print("=========================================================")
    
    # Write certificate and key to temporary files for requests
    cert_data = GWM_GENERAL_CER.strip()
    try:
        key_data = setup_client_key(cert_data, GWM_GENERAL_KEY_B64)
    except Exception as e:
        if not json_mode:
            print(f"Error preparing client keys: {e}")
        return

    cert_path = '/tmp/gwm_general.cer'
    key_path = '/tmp/gwm_general.key'

    with open(cert_path, 'w') as f:
        f.write(cert_data + "\n" + GWM_ROOT_PEM.strip())
    with open(key_path, 'wb') as f:
        f.write(key_data)

    config = load_config()
    
    # Check if we can reuse the cached token
    if config and config.get("accessToken"):
        if not json_mode:
            print("[+] Konfiguration geladen. Überprüfe bestehende Sitzung...")
        country = config.get("country", "DE")
        access_token = config["accessToken"]
    else:
        # Check if config has credentials or we need to login
        config = perform_fresh_login(config, json_mode)
        if not config:
            return
        country = config.get("country", "DE")
        access_token = config["accessToken"]

    headers_h5 = {
        "rs": "2",
        "terminal": "GW_APP_ORA",
        "brand": "3",
        "language": "de",
        "systemType": "1",
        "cver": "",
        "country": country
    }

    headers_app = {
        "rs": "2",
        "terminal": "GW_APP_ORA",
        "brand": "3",
        "country": country,
        "accessToken": access_token
    }
    
    vehicles_url = "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles"
    
    try:
        response = requests.get(
            vehicles_url, 
            headers=headers_app, 
            cert=(cert_path, key_path), 
            verify=True
        )
        
        # If the token is invalid/expired (HTTP 401 or GWM token expired error)
        resp_json = response.json() if response.status_code == 200 else {}
        resp_code = str(resp_json.get("code", ""))
        resp_desc = str(resp_json.get("description", "")).lower()
        if response.status_code == 401 or resp_code.startswith("1107") or resp_code == "550004" or "token" in resp_desc:
            if not json_mode:
                print("[-] Access-Token abgelaufen oder ungültig.")
            
            refreshed = False
            if config and refresh_token(config, headers_h5):
                refreshed = True
            else:
                if not json_mode:
                    print("[+] Token-Refresh fehlgeschlagen. Versuche erneute Anmeldung...")
                config = perform_fresh_login(config, json_mode)
                if config:
                    refreshed = True

            if refreshed:
                # Retry request with new token
                access_token = config["accessToken"]
                headers_app["accessToken"] = access_token
                response = requests.get(
                    vehicles_url, 
                    headers=headers_app, 
                    cert=(cert_path, key_path), 
                    verify=True
                )
            else:
                if not json_mode:
                    print("[-] Anmeldung und Refresh fehlgeschlagen. Bitte überprüfen Sie Ihre Zugangsdaten.")
                return

        if response.status_code != 200:
            if not json_mode:
                print(f"[-] HTTP Fehler beim Laden der Fahrzeuge: {response.status_code}")
            else:
                print(json.dumps({"error": f"HTTP {response.status_code} on acquireVehicles"}))
            return
            
        vehicles_data = response.json()
        if vehicles_data.get("code") != "000000":
            if not json_mode:
                print(f"[-] Fehler beim Laden der Fahrzeuge: {vehicles_data.get('description')}")
            else:
                print(json.dumps({"error": vehicles_data.get('description')}))
            return
            
        vehicles = vehicles_data.get("data", [])
        if not vehicles:
            if not json_mode:
                print("[-] Keine Fahrzeuge in diesem Account gefunden.")
            else:
                print(json.dumps({}))
            return
            
        for vehicle in vehicles:
            vin = vehicle["vin"]
            series_name = vehicle.get("appShowSeriesName", "ORA 03")
            
            status_url = f"https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/vehicle/getLastStatus?vin={vin}&seqNo="
            
            response = requests.get(
                status_url, 
                headers=headers_app, 
                cert=(cert_path, key_path), 
                verify=True
            )
            
            if response.status_code != 200:
                if not json_mode:
                    print(f"[-] HTTP Fehler beim Laden des Status: {response.status_code}")
                continue
                
            status_data = response.json()
            if status_data.get("code") != "000000":
                if not json_mode:
                    print(f"[-] Fehler beim Laden des Status: {status_data.get('description')}")
                continue
                
            items = status_data.get("data", {}).get("items", [])
            
            # Map of GWM API codes to JSON key names and casting functions
            code_mapping = {
                "2013021": ("soc", int),
                "2011501": ("range", int),
                "2103010": ("odometer", int),
                "2042082": ("charging_plugged", int),
                "2041142": ("charging_active", int),
                "2013022": ("charging_duration_minutes", int),
                "2041301": ("soce", int),
                "2101001": ("tire_pressure_fl", float),
                "2101002": ("tire_pressure_fr", float),
                "2101003": ("tire_pressure_rl", float),
                "2101004": ("tire_pressure_rr", float),
                "2101005": ("tire_temperature_fl", int),
                "2101006": ("tire_temperature_fr", int),
                "2101007": ("tire_temperature_rl", int),
                "2101008": ("tire_temperature_rr", int),
                "2210001": ("window_fl_closed", int),
                "2210002": ("window_fr_closed", int),
                "2210003": ("window_rl_closed", int),
                "2210004": ("window_rr_closed", int),
                "2210005": ("sunroof_state", int),
                "2210010": ("door_fl_closed", int),
                "2210011": ("door_fr_closed", int),
                "2210012": ("door_rl_closed", int),
                "2210013": ("door_rr_closed", int),
                "2222001": ("trunk_closed", int),
                "2310001": ("hood_closed", int),
                "2208001": ("locked", int),
                "2201001": ("cabin_temperature", lambda v: float(v) / 10.0 if v is not None else None),
                "2202001": ("climate_active", int),
                "2220001": ("seat_heating_fl", int),
                "2220002": ("seat_heating_fr", int),
                "2220003": ("seat_heating_rl", int),
                "2220004": ("seat_heating_rr", int)
            }
            
            telemetry = {}
            for item in items:
                code = item.get("code")
                val = item.get("value")
                if code in code_mapping:
                    key, cast_func = code_mapping[code]
                    try:
                        telemetry[key] = cast_func(val) if val is not None else None
                    except Exception:
                        telemetry[key] = val

            # Calculate charging status string
            charging_active = telemetry.get("charging_active")
            charging_plugged = telemetry.get("charging_plugged")
            charging_status = "Unbekannt"
            if charging_active is not None:
                if str(charging_active) == "1" or charging_active is True:
                    charging_status = "Lädt"
                elif str(charging_active) == "0" or charging_active is False:
                    if str(charging_plugged) == "1" or charging_plugged is True:
                        charging_status = "Angeschlossen (Inaktiv)"
                    else:
                        charging_status = "Getrennt"
            telemetry["charging_status"] = charging_status

            if json_mode:
                # Output clean JSON for Home Assistant command sensor with all data points
                ha_output = {
                    "vin": vin,
                    "series_name": series_name,
                    **telemetry
                }
                print(json.dumps(ha_output, indent=2))
            else:
                soc = telemetry.get("soc")
                range_val = telemetry.get("range")
                odometer = telemetry.get("odometer")
                print(f"\n[+] Fahrzeug gefunden: {series_name} (VIN: {vin})")
                print("\n================ ERGEBNISSE ================")
                print(f"1. SOC (Ladestand):      {soc}%" if soc is not None else "1. SOC (Ladestand):      Nicht verfügbar")
                print(f"2. Reichweite:           {range_val} km" if range_val is not None else "2. Reichweite:           Nicht verfügbar")
                print(f"3. Kilometerstand:       {odometer} km" if odometer is not None else "3. Kilometerstand:       Nicht verfügbar")
                print(f"4. Ladestatus:           {charging_status}")
                print("============================================\n")
            
    except Exception as e:
        if not json_mode:
            print(f"[-] Ein Fehler ist aufgetreten: {e}")
        else:
            print(json.dumps({"error": str(e)}))
        return

if __name__ == '__main__':
    main()
