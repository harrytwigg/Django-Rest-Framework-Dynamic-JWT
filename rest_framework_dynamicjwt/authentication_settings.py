from .models import AuthenticationSettingsModel
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from .serializers import AuthenticationSettingsSerializer


def generate_authentication_settings(custom_settings: dict = None) -> AuthenticationSettingsModel:
    """Creates a default authentication settings instance"""

    authentication_settings = AuthenticationSettingsModel(**generate_authentication_settings(custom_settings).validated_data)
    authentication_settings.save()
    return authentication_settings


def generate_authentication_settings(custom_settings: dict = None) -> AuthenticationSettingsSerializer:
    """Creates an authentication settings instance"""

    data = dict(custom_settings)

    if ('signing_key' not in data) or ('verifying_key' not in data):
        data.pop('signing_key', None)
        data.pop('verifying_key', None)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        data['signing_key'] = pem.decode()

        public_key = private_key.public_key()

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        data['verifying_key'] = pem_public.decode()

    result_serializer = AuthenticationSettingsSerializer(data=data)
    result_serializer.is_valid()

    return result_serializer

