import base64
import json
from typing import List

from django.conf import settings
from webauthn import generate_registration_options, options_to_json, verify_registration_response, \
    generate_authentication_options, verify_authentication_response
from webauthn.helpers import generate_challenge
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, PublicKeyCredentialType, \
    AttestationConveyancePreference, AuthenticatorSelectionCriteria, UserVerificationRequirement

from UserAuth.models import WebAuthnCredential
from Users.models import User

user_verification = UserVerificationRequirement.REQUIRED


def get_authenticators(user: User) -> List[PublicKeyCredentialDescriptor]:
    credentials = WebAuthnCredential.objects.filter(authentication__user_id=user.id)
    return [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=credential.credential_id,
        )
        for credential in credentials
    ]


def generate_reg_options(user: User):
    user_id = str(user.id)
    email = user.email
    display_name = user.full_name

    challenge = generate_challenge()

    options = generate_registration_options(
        rp_id=settings.PASSKEY_SERVER_ID,
        rp_name=settings.PASSKEY_SERVER_NAME,
        user_id=str_to_bytes(user_id),
        user_display_name=display_name,
        exclude_credentials=get_authenticators(user),
        user_name=email,
        attestation=AttestationConveyancePreference.DIRECT,
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=user_verification,
        )
    )
    return challenge, json.loads(options_to_json(options))


def verify_reg_response(response: dict, challenge: bytes):
    verified_details = verify_registration_response(
        credential=response,
        expected_challenge=challenge,
        expected_rp_id=settings.PASSKEY_SERVER_ID,
        expected_origin=settings.FRONTEND_ORIGIN,
        require_user_verification=True,
    )
    return verified_details


def generate_auth_options(user: User = None):
    challenge = generate_challenge()
    allow_credentials = []
    if user is not None:
        allow_credentials = get_authenticators(user)
    options = generate_authentication_options(
        rp_id=settings.PASSKEY_SERVER_ID,
        challenge=challenge,
        timeout=12000,
        allow_credentials=allow_credentials,
        user_verification=user_verification
    )
    return challenge, json.loads(options_to_json(options))


def verify_auth_response(response: dict, credential: WebAuthnCredential, challenge: bytes):
    verification = verify_authentication_response(
        credential=response,
        expected_challenge=challenge,
        expected_rp_id=settings.PASSKEY_SERVER_ID,
        expected_origin=settings.FRONTEND_ORIGIN,
        credential_public_key=credential.credential_public_key,
        credential_current_sign_count=credential.sign_count,
        require_user_verification=True
    )
    credential.sign_count = verification.new_sign_count
    credential.credential_device_type = verification.credential_device_type.value
    credential.credential_backed_up = verification.credential_backed_up
    credential.save()
    return verification, credential


# Convert bytes to a base64-encoded string
def bytes_to_str(byte_data: bytes) -> str:
    return base64.urlsafe_b64encode(byte_data).decode('utf-8')


# Convert a base64-encoded string back to bytes
def str_to_bytes(string: str) -> bytes:
    return base64.urlsafe_b64decode(string)
