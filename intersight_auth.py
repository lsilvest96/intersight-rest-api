"""
    intersight_auth.py -  provides a class to support Cisco Intersight
    interactions

    author: Chris Gascoigne (cgascoig@cisco.com)
"""
# pylint: disable=too-few-public-methods
from base64 import b64encode
from email.utils import formatdate
from six.moves.urllib.parse import urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from requests.auth import AuthBase

def _get_sha256_digest(data):

    hasher = hashes.Hash(hashes.SHA256(), default_backend())

    if data is not None:
        hasher.update(data.encode())

    return hasher.finalize()


def _prepare_string_to_sign(req_tgt, hdrs):
    """
    :param req_tgt : Request Target as stored in http header.
    :param hdrs: HTTP Headers to be signed.
    :return: instance of digest object
    """

    signature_string = '(request-target): ' + req_tgt + '\n'

    for i, (key, value) in enumerate(hdrs.items()):
        signature_string += key.lower() + ': ' + value
        if i < len(hdrs.items())-1:
            signature_string += '\n'

    return signature_string


def _get_sig_base64(key, string_to_sign):
    if isinstance(key, rsa.RSAPrivateKey):
        return b64encode(key.sign(string_to_sign, padding.PKCS1v15(), hashes.SHA256()))
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        return b64encode(key.sign(string_to_sign, ec.ECDSA(hashes.SHA256())))
    else:
        raise ValueError(f"unsupported key type: '{type(key).__name__}'")

def _get_signing_scheme(key):
    if isinstance(key, rsa.RSAPrivateKey):
        return 'rsa-sha256'
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        return 'hs2019'
    else:
        raise ValueError(f"unsupported key type: '{type(key).__name__}'")

def _get_auth_header(signing_headers, method, path, api_key_id, secret_key):

    string_to_sign = _prepare_string_to_sign(method.lower() + " " + path, signing_headers)
    b64_signed_auth_digest = _get_sig_base64(secret_key, string_to_sign.encode())

    auth_str = (
        f'Signature keyId="{api_key_id}",algorithm="{_get_signing_scheme(secret_key)}",headers="(request-target)'
        )

    for key in signing_headers:
        auth_str += ' ' + key.lower()

    auth_str += (
        '", signature="' + b64_signed_auth_digest.decode('ascii') + '"'
        )

    return auth_str


class IntersightAuth(AuthBase):
    """Implements requests custom authentication for Cisco Intersight"""

    def __init__(self, secret_key_filename, api_key_id, secret_key_file_password=None):
        self.secret_key_filename = secret_key_filename
        self.api_key_id = api_key_id
        self.secret_key_file_password = secret_key_file_password
        with open(secret_key_filename, "rb") as secret_key_file:
            self.secret_key = serialization.load_pem_private_key(
                secret_key_file.read(),
                password=secret_key_file_password,
                backend=default_backend()
                )

    def __call__(self, r):
        """Called by requests to modify and return the authenticated request"""
        date = formatdate(timeval=None, localtime=False, usegmt=True)
        # date = "Tue, 07 Aug 2018 04:03:47 GMT"

        digest = _get_sha256_digest(r.body)

        url = urlparse(r.url)
        path = url.path or "/"
        if url.query:
            path += "?"+url.query

        signing_headers = {
            "Date": date,
            "Host": url.hostname,
            "Content-Type": r.headers.get('Content-Type') or "application/json",
            "Digest": "SHA-256=%s" % b64encode(digest).decode('ascii'),
        }

        auth_header = _get_auth_header(
            signing_headers, r.method, path, self.api_key_id, self.secret_key)

        r.headers['Digest'] = "SHA-256=%s" % b64encode(digest).decode('ascii')
        r.headers['Date'] = date
        r.headers['Authorization'] = "%s" % auth_header
        r.headers['Host'] = url.hostname
        r.headers['Content-Type'] = signing_headers['Content-Type']

        return r