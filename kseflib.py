import base64
import logging
import datetime
import argparse
import os
import re
import hashlib
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives import hashes, padding as symmetric_padding
from cryptography.x509 import Certificate, load_pem_x509_certificate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import \
    EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import (
    pkcs12,
    Encoding,
    load_pem_private_key
)

from signxml import methods
from signxml.xades import XAdESSigner

from lxml import etree

import requests

KSEF_API_HOST = "api-test.ksef.mf.gov.pl"
KSEF_API_VERSION = "2"

# XML Namespaces
NS_AUTH = "http://ksef.mf.gov.pl/auth/token/2.0"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
NS_XADES = "http://uri.etsi.org/01903/v1.3.2#"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
NS_XSD = "http://www.w3.org/2001/XMLSchema"

challenge_pattern_rxp = re.compile(r"^[A-Z0-9\-]+$")
nip_pattern_rxp = re.compile(f"^[0-9]+$")

logger = logging.getLogger(__name__)

_ksef_api_host: str | None = None

auth_token_request_tmpl = """
<?xml version="1.0" encoding="utf-8"?>
<AuthTokenRequest xmlns="http://ksef.mf.gov.pl/auth/token/2.0"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Challenge>$CHALLENGE</Challenge>
  <ContextIdentifier>
    <Nip>$NIP</Nip>
  </ContextIdentifier>
  <SubjectIdentifierType>certificateSubject</SubjectIdentifierType>
</AuthTokenRequest>
"""

sample_invoice = """
<?xml version="1.0" encoding="UTF-8"?>
  <Faktura xmlns="http://crd.gov.pl/wzor/2023/06/29/12648/">
      <Naglowek>
          <KodFormularza kodSystemowy="FA(3)" wersjaSchemy="1-0E">FA</KodFormularza>
          <WariantFormularza>3</WariantFormularza>
          <DataWytworzeniaFa>2026-02-01T12:00:00Z</DataWytworzeniaFa>
          <SystemInfo>My System</SystemInfo>
      </Naglowek>
      <!-- Add your invoice data here -->
  </Faktura>
"""


@dataclass
class RemoteCertificate:
    """A certificate"""
    body: str
    usage: list[str]
    valid_from: datetime.datetime
    valid_to: datetime.datetime

    @classmethod
    def from_dict(cls, ns: dict) -> "RemoteCertificate":
        return cls(
            body=ns["certificate"],
            usage=ns["usage"],
            valid_from=datetime.datetime.fromisoformat(ns["validFrom"]),
            valid_to=datetime.datetime.fromisoformat(ns["validTo"]),
        )

    def as_pem_str(self) -> str:
        """Convert to PEM format"""
        return (
            f"-----BEGIN CERTIFICATE-----\n"
            f"{self.body}\n"
            f"-----END CERTIFICATE-----"
        )


@dataclass
class Challenge:
    body: str
    timestamp: datetime.datetime

    @classmethod
    def from_dict(cls, ns: dict) -> "Challenge":
        return cls(
            ns["challenge"],
            timestamp=datetime.datetime.fromisoformat(ns["timestamp"]),
        )


@dataclass
class AuthenticationToken:
    """Authentication token"""
    body: str
    valid_until: datetime.datetime

    @classmethod
    def from_dict(cls, ns: dict) -> "AuthenticationToken":
        return cls(
            body=ns["token"],
            valid_until=datetime.datetime.fromisoformat(ns["validUntil"]),
        )


@dataclass
class Reference:
    number: str
    authentication_token: AuthenticationToken

    @classmethod
    def from_dict(cls, ns: dict) -> "Reference":
        return cls(
            number=ns["referenceNumber"],
            authentication_token=AuthenticationToken.from_dict(
                ns["authenticationToken"]
            )
        )


@dataclass
class Token:
    token_type: Literal["access", "refresh"] | None
    body: str
    valid_until: datetime.datetime

    @classmethod
    def from_dict(cls, ns: dict, token_type: str | None) -> "Token":
        return cls(
            token_type=token_type,
            body=ns["token"],
            valid_until=datetime.datetime.fromisoformat(ns["validUntil"]),
        )


@dataclass
class Session:
    """A session"""
    reference_number: str
    valid_until: datetime.datetime

    @classmethod
    def from_dict(cls, ns: dict) -> "Session":
        return cls(
            reference_number=ns["referenceNumber"],
            valid_until=datetime.datetime.fromisoformat(ns["validUntil"]),
        )


def get_public_certificates() -> tuple[RemoteCertificate, RemoteCertificate]:
    """Get the KSeF public certificates"""
    url = f"https://{_ksef_api_host}/v{KSEF_API_VERSION}/security/public-key-certificates"
    logger.debug("Requesting public certificates at %s ...", url)
    response = requests.get(
        url,
        headers={
            "Content-Type": "application/json",
        }
    )
    logger.debug("Got response %s", response)
    if response.status_code != 200:
        raise Exception("Failed to get public certificates")
    certs = (
        RemoteCertificate.from_dict(ns) for ns in response.json()
    )
    auth_cert = next(certs)
    invoice_cert = next(certs)
    try:
        next(certs)
    except StopIteration:
        return (auth_cert, invoice_cert)
    else:
        raise Exception(
            "Unsupported scenario: more than two certificates found."
        )


def get_auth_challenge() -> Challenge:
    """Get authentication challenge from KSeF API."""
    url = f"https://{_ksef_api_host}/v{KSEF_API_VERSION}/auth/challenge"
    response = requests.post(url)
    response.raise_for_status()
    return Challenge.from_dict(response.json())


def load_p12(
        path: str,
        password: bytes | None = None
) -> tuple[RSAPrivateKey | EllipticCurvePrivateKey, Certificate]:
    """Load a private key from a file."""
    with open(path, "rb") as f:
        p12_data = f.read()

    private_key, certificate, _chain = pkcs12.load_key_and_certificates(
        data=p12_data,
        password=password
    )
    return (private_key, certificate)


def read_private_key(path: str,
                     password: bytes | None = None) -> RSAPrivateKey | EllipticCurvePrivateKey:
    """Load a PEM private key from a file"""
    with open(path, "rb") as fd:
        private_key_pem = fd.read()

    return load_pem_private_key(
        private_key_pem,
        password=password,
        backend=default_backend()
    )


def read_pem_certificate(path: str) -> Certificate:
    """Load a PEM certificate from a file"""
    with open(path, "rb") as fd:
        certificate_pem = fd.read()

    return load_pem_x509_certificate(
        certificate_pem,
        backend=default_backend()
    )


def create_auth_token_request_document(challenge: Challenge,
                                       nip: str) -> str:
    """Create a KSeF auth token request."""
    if not challenge_pattern_rxp.match(challenge.body):
        raise ValueError(f"Invalid challenge body: {challenge.body}")

    if not nip_pattern_rxp.match(nip):
        raise ValueError(f"Invalid NIP number: {nip}")
    doc = auth_token_request_tmpl.strip().replace(
        "$CHALLENGE",
        challenge.body
    )
    doc = doc.replace("$NIP", nip)
    return doc


def sign_auth_token_request(request_doc: str,
                            key: RSAPrivateKey | EllipticCurvePrivateKey,
                            cert: Certificate | RemoteCertificate) -> str:
    """Sign a KSeF auth token request with XAdES signature."""

    cert_pem = cert.public_bytes(encoding=Encoding.PEM)
    parser = etree.XMLParser(
        ns_clean=True,
        resolve_entities=False,
        no_network=True
    )
    root = etree.fromstring(request_doc.encode(), parser)
    logger.debug(f"Signing document")

    # Detect key type and use appropriate signature algorithm
    # EC keys have a 'curve' attribute, RSA keys don't
    if hasattr(key, 'curve'):
        signature_algorithm = "ecdsa-sha256"
    else:
        signature_algorithm = "rsa-sha256"

    # Use XAdESSigner for proper XAdES signature format with XAdES-BES profile
    signer = XAdESSigner(
        method=methods.enveloped,
        signature_algorithm=signature_algorithm,
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    )

    signed_root = signer.sign(root, key=key, cert=cert_pem.decode())
    return etree.tostring(signed_root, encoding='unicode')


def authenticate(signed_doc: str) -> Reference:
    """Authenticate a KSeF auth token request."""
    url = f"https://{_ksef_api_host}/v{KSEF_API_VERSION}/auth/xades-signature"
    headers = {"Content-Type": "application/xml"}
    response = requests.post(url, data=signed_doc, headers=headers)
    response.raise_for_status()
    return Reference.from_dict(response.json())


def get_tokens(auth_token: AuthenticationToken) -> tuple[Token, Token]:
    """Get an access token."""
    url = f"https://{_ksef_api_host}/v{KSEF_API_VERSION}/auth/token/redeem"
    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {auth_token.body}"
        }
    )
    response.raise_for_status()
    token_ns = response.json()
    return (
        Token.from_dict(
            token_ns["accessToken"],
            token_type="access",
        ),
        Token.from_dict(
            token_ns["refreshToken"],
            token_type="refresh",
        ),
    )


def create_temporary_symmetric_key() -> tuple[bytes, bytes]:
    """Create a temporary symmetric key and IV"""
    return (os.urandom(32), os.urandom(16))


def encrypt_key(symmetric_key_pem: bytes,
                public_cert: RemoteCertificate) -> bytes:
    """Encrypt a symmetric key using a given public key."""
    ksef_cert = load_pem_x509_certificate(public_cert.as_pem_str().encode())
    public_key = ksef_cert.public_key()
    encrypted_key = public_key.encrypt(
        symmetric_key_pem,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def open_session(
        encrypted_key: bytes,
        access_token: Token,
        iv: bytes
) -> Session:
    """Open a KSef session."""
    url = f"https://{_ksef_api_host}/v{KSEF_API_VERSION}/sessions/online"
    session_data = {
        "formCode": {
            "systemCode": "FA (3)",
            "schemaVersion": "1-0E",
            "value": "FA"

        },
        "encryption": {
            "encryptedSymmetricKey": base64.b64encode(encrypted_key).decode(
                "ascii"
            ),
            "InitializationVector": base64.b64encode(iv).decode("ascii")
        }
    }
    response = requests.post(
        url,
        json=session_data,
        headers={
            "Authorization": f"Bearer {access_token.body}",
            "Content-Type": "application/json"
        }
    )
    logger.debug(response.text)
    response.raise_for_status()
    session = response.json()
    return Session.from_dict(session)


def encrypt_invoice(invoice_xml: str, symmetric_key: bytes, iv: bytes) -> dict:
    """Encrypt an invoice."""
    invoice_bytes = invoice_xml.encode()
    clear_hash = hashlib.sha256(invoice_bytes).digest()
    clear_size = len(invoice_bytes)

    padder = symmetric_padding.PKCS7(128).padder()
    padded_data = padder.update(invoice_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_invoice = encryptor.update(padded_data)
    encrypted_invoice += encryptor.finalize()
    encrypted_hash = hashlib.sha256(encrypted_invoice).digest()
    encrypted_size = len(encrypted_invoice)
    return {
        "invoiceHash": base64.b64encode(clear_hash).decode("ascii"),
        "invoiceSize": clear_size,
        "encryptedInvoiceHash": base64.b64encode(encrypted_hash).decode(
            "ascii"),
        "encryptedInvoiceSize": encrypted_size,
        "encryptedInvoiceContent": base64.b64encode(encrypted_invoice).decode(
            "ascii"
        ),
        "offlineMode": False,
        "hashOfCorrectedInvoice": None
    }


def send_encrypted_invoice_data(
        encrypted_invoice_data: dict,
        access_token: Token,
        session: Session,
) -> dict:
    """Send an encrypted invoice data."""
    url = (
        f"https://{_ksef_api_host}/v{KSEF_API_VERSION}"
        f"/sessions/online/{session.reference_number}/invoices"
    )
    response = requests.post(
        url,
        json=encrypted_invoice_data,
        headers={
            "Authorization": f"Bearer {access_token.body}",
            "Content-Type": "application/json"
        }
    )
    logger.debug(response.text)
    response.raise_for_status()
    response_data = response.json()
    return response_data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("NIP")
    parser.add_argument("certificate_file_path")
    parser.add_argument(
        "--private_key_file_path",
        "-k",
        default=None,
        required=False
    )
    parser.add_argument(
        "--public_key_password",
        "-p",
        default=None,
        required=False,
        type=lambda s: s.encode()
    )
    parser.add_argument(
        "--api-host",
        "-a",
        default=KSEF_API_HOST,
        required=False
    )
    args = parser.parse_args()
    nip = args.NIP
    if key_path := args.private_key_file_path:
        key = read_private_key(key_path, args.public_key_password)
        cert = read_pem_certificate(args.certificate_file_path)
    else:
        logger.debug(
            "No private key file provided. Assuming a p12 certificate"
        )
        key, cert = load_p12(args.certificate_file_path)

    global _ksef_api_host
    _ksef_api_host = args.api_host

    challenge = get_auth_challenge()
    _, invoice_cert = get_public_certificates()
    request_doc = create_auth_token_request_document(challenge, nip)
    signed_doc = sign_auth_token_request(request_doc, key, cert)
    reference = authenticate(signed_doc)
    access_token, refresh_token = get_tokens(reference.authentication_token)
    symmetric_key, iv = create_temporary_symmetric_key()
    encrypted_key = encrypt_key(symmetric_key, invoice_cert)
    session = open_session(encrypted_key, access_token, iv)
    invoice_data = encrypt_invoice(sample_invoice, symmetric_key, iv)
    outcome = send_encrypted_invoice_data(invoice_data, access_token, session)
    print(outcome)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
