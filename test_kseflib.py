import os
import base64
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from unittest.mock import Mock, mock_open, patch

import pytest

import kseflib


@pytest.fixture
def rsa_private_key():
    """Generate an RSA private key for testing."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


@pytest.fixture
def ec_private_key():
    """Generate an EC private key for testing."""
    return ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )


@pytest.fixture
def certificate(rsa_private_key):
    """Generate a self-signed certificate for testing."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        rsa_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(rsa_private_key, hashes.SHA256(), default_backend())

    return cert


@pytest.fixture
def certificate_pem(certificate):
    """Get certificate in PEM format."""
    return certificate.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def private_key_pem(rsa_private_key):
    """Get private key in PEM format."""
    return rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


# Tests for RemoteCertificate class


class TestRemoteCertificate:
    def test_from_dict(self):
        """Test creating RemoteCertificate from dictionary."""
        data = {
            "certificate": "MIIC...",
            "usage": ["auth", "encryption"],
            "validFrom": "2024-01-01T00:00:00Z",
            "validTo": "2025-01-01T00:00:00Z"
        }
        cert = kseflib.RemoteCertificate.from_dict(data)

        assert cert.body == "MIIC..."
        assert cert.usage == ["auth", "encryption"]
        assert cert.valid_from == datetime.datetime(2024, 1, 1, 0, 0, 0,
                                                    tzinfo=datetime.timezone.utc)
        assert cert.valid_to == datetime.datetime(2025, 1, 1, 0, 0, 0,
                                                  tzinfo=datetime.timezone.utc)

    def test_as_pem_str(self):
        """Test converting RemoteCertificate to PEM format."""
        cert = kseflib.RemoteCertificate(
            body="MIIC123ABC",
            usage=["auth"],
            valid_from=datetime.datetime(2024, 1, 1),
            valid_to=datetime.datetime(2025, 1, 1)
        )
        pem = cert.as_pem_str()

        assert pem.startswith("-----BEGIN CERTIFICATE-----")
        assert pem.endswith("-----END CERTIFICATE-----")
        assert "MIIC123ABC" in pem


# Tests for Challenge class


class TestChallenge:
    def test_from_dict(self):
        """Test creating Challenge from dictionary."""
        data = {
            "challenge": "abc123",
            "timestamp": "2024-01-01T12:00:00Z"
        }
        challenge = kseflib.Challenge.from_dict(data)

        assert challenge.body == "abc123"
        assert challenge.timestamp == datetime.datetime(2024, 1, 1, 12, 0, 0,
                                                        tzinfo=datetime.timezone.utc)


# Tests for AuthenticationToken class


class TestAuthenticationToken:
    def test_from_dict(self):
        """Test creating AuthenticationToken from dictionary."""
        data = {
            "token": "token123",
            "validUntil": "2024-01-01T23:59:59Z"
        }
        token = kseflib.AuthenticationToken.from_dict(data)

        assert token.body == "token123"
        assert token.valid_until == datetime.datetime(2024, 1, 1, 23, 59, 59,
                                                      tzinfo=datetime.timezone.utc)


# Tests for Reference class


class TestReference:
    def test_from_dict(self):
        """Test creating Reference from dictionary."""
        data = {
            "referenceNumber": "REF123",
            "authenticationToken": {
                "token": "token456",
                "validUntil": "2024-01-01T23:59:59Z"
            }
        }
        ref = kseflib.Reference.from_dict(data)

        assert ref.number == "REF123"
        assert ref.authentication_token.body == "token456"
        assert ref.authentication_token.valid_until == datetime.datetime(2024,
                                                                         1, 1,
                                                                         23,
                                                                         59,
                                                                         59,
                                                                         tzinfo=datetime.timezone.utc)


# Tests for Token class


class TestToken:
    def test_from_dict_access_token(self):
        """Test creating access Token from dictionary."""
        data = {
            "token": "access_token_123",
            "validUntil": "2024-01-01T23:59:59Z"
        }
        token = kseflib.Token.from_dict(data, "access")

        assert token.token_type == "access"
        assert token.body == "access_token_123"
        assert token.valid_until == datetime.datetime(2024, 1, 1, 23, 59, 59,
                                                      tzinfo=datetime.timezone.utc)

    def test_from_dict_refresh_token(self):
        """Test creating refresh Token from dictionary."""
        data = {
            "token": "refresh_token_456",
            "validUntil": "2024-01-02T23:59:59Z"
        }
        token = kseflib.Token.from_dict(data, "refresh")

        assert token.token_type == "refresh"
        assert token.body == "refresh_token_456"


# Tests for Session class


class TestSession:
    def test_from_dict(self):
        """Test creating Session from dictionary."""
        data = {
            "referenceNumber": "SESSION123",
            "validUntil": "2024-01-01T23:59:59Z"
        }
        session = kseflib.Session.from_dict(data)

        assert session.reference_number == "SESSION123"
        assert session.valid_until == datetime.datetime(2024, 1, 1, 23, 59, 59,
                                                        tzinfo=datetime.timezone.utc)


# Tests for API functions


class TestGetPublicCertificates:
    @patch('kseflib.requests.get')
    def test_get_public_certificates_success(self, mock_get):
        """Test successful retrieval of public certificates."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "certificate": "CERT1",
                "usage": ["auth"],
                "validFrom": "2024-01-01T00:00:00Z",
                "validTo": "2025-01-01T00:00:00Z"
            },
            {
                "certificate": "CERT2",
                "usage": ["encryption"],
                "validFrom": "2024-01-01T00:00:00Z",
                "validTo": "2025-01-01T00:00:00Z"
            }
        ]
        mock_get.return_value = mock_response

        certs = kseflib.get_public_certificates()

        assert len(certs) == 2
        assert certs[0].body == "CERT1"
        assert certs[1].body == "CERT2"
        mock_get.assert_called_once()

    @patch('kseflib.requests.get')
    def test_get_public_certificates_failure(self, mock_get):
        """Test failure when retrieving public certificates."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        with pytest.raises(Exception,
                           match="Failed to get public certificates"):
            kseflib.get_public_certificates()


class TestGetAuthChallenge:
    @patch('kseflib.requests.post')
    def test_get_auth_challenge_success(self, mock_post):
        """Test successful retrieval of auth challenge."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "challenge": "challenge123",
            "timestamp": "2024-01-01T12:00:00Z"
        }
        mock_post.return_value = mock_response

        challenge = kseflib.get_auth_challenge()

        assert challenge.body == "challenge123"
        assert challenge.timestamp == datetime.datetime(2024, 1, 1, 12, 0, 0,
                                                        tzinfo=datetime.timezone.utc)
        mock_post.assert_called_once()


# Tests for certificate and key loading functions


class TestLoadP12:
    @patch('builtins.open', new_callable=mock_open, read_data=b'p12data')
    @patch('kseflib.pkcs12.load_key_and_certificates')
    def test_load_p12(self, mock_load, mock_file, rsa_private_key,
                      certificate):
        """Test loading PKCS12 file."""
        mock_load.return_value = (rsa_private_key, certificate, [])

        key, cert = kseflib.load_p12("/path/to/cert.p12")

        assert key == rsa_private_key
        assert cert == certificate
        mock_file.assert_called_once_with("/path/to/cert.p12", "rb")


class TestReadPrivateKey:
    def test_read_private_key(self, private_key_pem):
        """Test reading PEM private key from file."""
        with patch('builtins.open', mock_open(read_data=private_key_pem)):
            key = kseflib.read_private_key("/path/to/key.pem")
            assert key is not None

    def test_read_private_key_with_password(self, rsa_private_key):
        """Test reading encrypted PEM private key."""
        encrypted_pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                b"password")
        )

        with patch('builtins.open', mock_open(read_data=encrypted_pem)):
            key = kseflib.read_private_key("/path/to/key.pem", b"password")
            assert key is not None


class TestReadPemCertificate:
    def test_read_pem_certificate(self, certificate_pem):
        """Test reading PEM certificate from file."""
        with patch('builtins.open', mock_open(read_data=certificate_pem)):
            cert = kseflib.read_pem_certificate("/path/to/cert.pem")
            assert cert is not None


# Tests for document creation and signing


class TestCreateAuthTokenRequestDocument:
    def test_create_auth_token_request_document(self):
        """Test creating auth token request document."""
        challenge_body = "20260207-CR-20174E1234-000DADA000-10"
        challenge = kseflib.Challenge(
            body=challenge_body,
            timestamp=datetime.datetime(2024, 1, 1, 12, 0, 0)
        )
        nip = "1234567890"

        doc = kseflib.create_auth_token_request_document(challenge, nip)

        assert challenge_body in doc
        assert "1234567890" in doc
        assert "AuthTokenRequest" in doc
        assert "certificateSubject" in doc


class TestSignAuthTokenRequest:
    def test_sign_auth_token_request_rsa(self, rsa_private_key, certificate):
        """Test signing auth token request with RSA key."""
        request_doc = """<?xml version="1.0" encoding="utf-8"?>
<AuthTokenRequest xmlns="http://ksef.mf.gov.pl/auth/token/2.0">
  <Challenge>test_challenge</Challenge>
  <ContextIdentifier>
    <Nip>1234567890</Nip>
  </ContextIdentifier>
  <SubjectIdentifierType>certificateSubject</SubjectIdentifierType>
</AuthTokenRequest>"""

        signed_doc = kseflib.sign_auth_token_request(request_doc,
                                                     rsa_private_key,
                                                     certificate)

        assert signed_doc is not None
        assert "Signature" in signed_doc
        assert isinstance(signed_doc, str)

    def test_sign_auth_token_request_ec(self, ec_private_key):
        """Test signing auth token request with EC key."""
        # Create EC certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ec_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(ec_private_key, hashes.SHA256(), default_backend())

        request_doc = """<?xml version="1.0" encoding="utf-8"?>
<AuthTokenRequest xmlns="http://ksef.mf.gov.pl/auth/token/2.0">
  <Challenge>test_challenge</Challenge>
  <ContextIdentifier>
    <Nip>1234567890</Nip>
  </ContextIdentifier>
  <SubjectIdentifierType>certificateSubject</SubjectIdentifierType>
</AuthTokenRequest>"""

        signed_doc = kseflib.sign_auth_token_request(request_doc,
                                                     ec_private_key, cert)

        assert signed_doc is not None
        assert "Signature" in signed_doc


class TestAuthenticate:
    @patch('kseflib.requests.post')
    def test_authenticate_success(self, mock_post):
        """Test successful authentication."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "referenceNumber": "REF123",
            "authenticationToken": {
                "token": "auth_token_456",
                "validUntil": "2024-01-01T23:59:59Z"
            }
        }
        mock_post.return_value = mock_response

        reference = kseflib.authenticate("<signed_doc/>")

        assert reference.number == "REF123"
        assert reference.authentication_token.body == "auth_token_456"
        mock_post.assert_called_once()


class TestGetTokens:
    @patch('kseflib.requests.post')
    def test_get_tokens_success(self, mock_post):
        """Test successful token retrieval."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "accessToken": {
                "token": "access_123",
                "validUntil": "2024-01-01T23:59:59Z"
            },
            "refreshToken": {
                "token": "refresh_456",
                "validUntil": "2024-01-02T23:59:59Z"
            }
        }
        mock_post.return_value = mock_response

        auth_token = kseflib.AuthenticationToken(
            body="auth_token",
            valid_until=datetime.datetime(2024, 1, 1, 23, 59, 59)
        )

        access_token, refresh_token = kseflib.get_tokens(auth_token)

        assert access_token.token_type == "access"
        assert access_token.body == "access_123"
        assert refresh_token.token_type == "refresh"
        assert refresh_token.body == "refresh_456"
        mock_post.assert_called_once()


# Tests for encryption functions


class TestCreateTemporarySymmetricKey:
    def test_create_temporary_symmetric_key(self):
        """Test creation of temporary symmetric key and IV."""
        key, iv = kseflib.create_temporary_symmetric_key()

        assert len(key) == 32  # 256-bit key
        assert len(iv) == 16  # 128-bit IV
        assert isinstance(key, bytes)
        assert isinstance(iv, bytes)

    def test_create_temporary_symmetric_key_randomness(self):
        """Test that generated keys are random."""
        key1, iv1 = kseflib.create_temporary_symmetric_key()
        key2, iv2 = kseflib.create_temporary_symmetric_key()

        assert key1 != key2
        assert iv1 != iv2


class TestEncryptKey:
    def test_encrypt_key(self, rsa_private_key):
        """Test symmetric key encryption."""
        # Create a certificate with RSA public key
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            rsa_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(rsa_private_key, hashes.SHA256(), default_backend())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        # Extract just the base64 data from PEM (remove header/footer)
        cert_lines = cert_pem.strip().split('\n')
        cert_b64 = ''.join(cert_lines[1:-1])

        remote_cert = kseflib.RemoteCertificate(
            body=cert_b64,
            usage=["encryption"],
            valid_from=datetime.datetime(2024, 1, 1),
            valid_to=datetime.datetime(2025, 1, 1)
        )

        symmetric_key = os.urandom(32)
        encrypted_key = kseflib.encrypt_key(symmetric_key, remote_cert)

        assert encrypted_key is not None
        assert isinstance(encrypted_key, bytes)
        assert len(encrypted_key) > 0


class TestOpenSession:
    @patch('kseflib.requests.post')
    def test_open_session_success(self, mock_post):
        """Test successful session opening."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "referenceNumber": "SESSION123",
            "validUntil": "2024-01-01T23:59:59Z"
        }
        mock_post.return_value = mock_response

        encrypted_key = b"encrypted_key_data"
        access_token = kseflib.Token(
            token_type="access",
            body="access_token",
            valid_until=datetime.datetime(2024, 1, 1, 23, 59, 59)
        )
        iv = os.urandom(16)

        session = kseflib.open_session(encrypted_key, access_token, iv)

        assert session.reference_number == "SESSION123"
        assert session.valid_until == datetime.datetime(2024, 1, 1, 23, 59, 59,
                                                        tzinfo=datetime.timezone.utc)
        mock_post.assert_called_once()


class TestEncryptInvoice:
    def test_encrypt_invoice(self):
        """Test invoice encryption."""
        invoice_xml = "<Invoice>test</Invoice>"
        symmetric_key = os.urandom(32)
        iv = os.urandom(16)

        result = kseflib.encrypt_invoice(invoice_xml, symmetric_key, iv)

        assert "invoiceHash" in result
        assert "invoiceSize" in result
        assert "encryptedInvoiceHash" in result
        assert "encryptedInvoiceSize" in result
        assert "encryptedInvoiceContent" in result
        assert result["offlineMode"] is False
        assert result["hashOfCorrectedInvoice"] is None

        # Verify sizes
        assert result["invoiceSize"] == len(invoice_xml.encode())
        assert result["encryptedInvoiceSize"] > result["invoiceSize"]

        # Verify hashes are base64 encoded
        base64.b64decode(result["invoiceHash"])
        base64.b64decode(result["encryptedInvoiceHash"])
        base64.b64decode(result["encryptedInvoiceContent"])

    def test_encrypt_invoice_produces_different_output(self):
        """Test that encryption with different IVs produces different output."""
        invoice_xml = "<Invoice>test</Invoice>"
        symmetric_key = os.urandom(32)
        iv1 = os.urandom(16)
        iv2 = os.urandom(16)

        result1 = kseflib.encrypt_invoice(invoice_xml, symmetric_key, iv1)
        result2 = kseflib.encrypt_invoice(invoice_xml, symmetric_key, iv2)

        # Same plaintext should have same hash
        assert result1["invoiceHash"] == result2["invoiceHash"]
        # Different IVs should produce different encrypted content
        assert result1["encryptedInvoiceContent"] != result2[
            "encryptedInvoiceContent"]


class TestSendEncryptedInvoiceData:
    @patch('kseflib.requests.post')
    def test_send_encrypted_invoice_data_success(self, mock_post):
        """Test successful sending of encrypted invoice data."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": "accepted",
            "invoiceNumber": "INV123"
        }
        mock_post.return_value = mock_response

        encrypted_invoice_data = {
            "invoiceHash": "hash123",
            "invoiceSize": 1000,
            "encryptedInvoiceHash": "enc_hash123",
            "encryptedInvoiceSize": 1024,
            "encryptedInvoiceContent": "base64_content",
            "offlineMode": False
        }

        access_token = kseflib.Token(
            token_type="access",
            body="access_token",
            valid_until=datetime.datetime(2024, 1, 1, 23, 59, 59)
        )

        session = kseflib.Session(
            reference_number="SESSION123",
            valid_until=datetime.datetime(2024, 1, 1, 23, 59, 59)
        )

        result = kseflib.send_encrypted_invoice_data(
            encrypted_invoice_data,
            access_token,
            session
        )

        assert result["status"] == "accepted"
        assert result["invoiceNumber"] == "INV123"
        mock_post.assert_called_once()
