# ===================
# author: peter lacko
# year: 2016
# ===================

from os import path
import OpenSSL

from django.conf import settings


class MyCertificateHandler(object):
    """Manages user certificate."""
    cert = None

    @classmethod
    def generate_new(self, csr):
        """Return PEM encoded certificate without BEGIN/END and nls."""
        cert = None
        k_path = path.join(settings.SECRET_KEY_PATH, 'certificate_signing_key.pem')
        c_path = path.join(settings.SECRET_KEY_PATH, 'certificate_signing_cert.pem')
        with open(k_path, "r") as f_key, open(c_path, "r") as f_cert:
            ca_cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, str.encode(f_cert.read()))
            ca_key = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, str.encode(f_key.read()))
            req = OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_PEM, csr)
            cert = OpenSSL.crypto.X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(1)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(1000 * 24 * 3600)
            cert.set_issuer(ca_cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(ca_key, "sha256")
        return OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
