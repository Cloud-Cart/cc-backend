import json
from typing import List

from django.conf import settings
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import generate_challenge
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, PublicKeyCredentialType, \
    AttestationConveyancePreference

from UserAuth.models import WebAuthnCredential
from Users.models import User


def get_authenticators(user: User) -> List[PublicKeyCredentialDescriptor]:
    credentials = WebAuthnCredential.objects.filter(authentication__user_id=user.id)
    return [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=credential.credential_id.encode('utf-8'),
        )
        for credential in credentials
    ]


def generate_reg_options(user: User):
    user_id = user.id
    email = user.email
    display_name = user.full_name

    challenge = generate_challenge()

    options = generate_registration_options(
        rp_id=settings.PASSKEY_SERVER_ID,
        rp_name=settings.PASSKEY_SERVER_NAME,
        user_id=str(user_id).encode('utf-8'),
        user_display_name=display_name,
        exclude_credentials=get_authenticators(user),
        user_name=email,
        attestation=AttestationConveyancePreference.DIRECT,
        challenge=challenge,
    )
    return challenge, json.loads(options_to_json(options))

def verify_reg_response(options: dict, challenge: bytes):
    verified_details = verify_registration_response(
        credential=options,
        expected_challenge=challenge,
        expected_rp_id=settings.PASSKEY_SERVER_ID,
        expected_origin=settings.FRONTEND_ORIGIN,
        require_user_verification=True,
    )
    return verified_details
