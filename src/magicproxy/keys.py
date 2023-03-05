import google.auth
import google.auth.crypt
from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from magicproxy.types import _Keys

_BACKEND = backends.default_backend()
_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)


class Keys(_Keys):
    @classmethod
    def from_files(cls, private_key_file, certificate_file):
        try:
            with open(private_key_file, "rb") as fh:
                private_key_bytes = fh.read()
                private_key = serialization.load_pem_private_key(
                    private_key_bytes, password=None, backend=_BACKEND
                )
                private_key_signer = google.auth.crypt.RSASigner.from_string(
                    private_key_bytes
                )

            with open(certificate_file, "rb") as fh:
                certificate_pem = fh.read()
                certificate = x509.load_pem_x509_certificate(certificate_pem, _BACKEND)
                public_key = certificate.public_key()
        except IOError:
            raise RuntimeError("I/O error, config file should be readable")
        return cls(
            private_key=private_key,
            private_key_signer=private_key_signer,
            public_key=public_key,
            certificate=certificate,
            certificate_pem=certificate_pem,
        )


if __name__ == "__main__":
    from magicproxy.config import load_config
    from magicproxy.crypto import generate_keys

    config = load_config(_load_keys=False)
    if config.public_access is None:
        raise RuntimeError("need a configured public access, to properly generate keys")
    generate_keys(config)
    print(f'generated the keys')
    print(config.private_key_location)
    print(config.public_key_location)
    print(config.public_certificate_location)
