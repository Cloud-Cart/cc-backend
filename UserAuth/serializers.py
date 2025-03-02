import os
import re
from datetime import datetime, timedelta
from typing import Optional

from django.core import signing
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError, PermissionDenied
from rest_framework.fields import CharField, SerializerMethodField, EmailField, UUIDField, JSONField
from rest_framework.serializers import ModelSerializer, Serializer
from webauthn import base64url_to_bytes
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse
from webauthn.registration.verify_registration_response import VerifiedRegistration

from UserAuth.choices import DefaultAuthenticationMethod
from UserAuth.models import Authentication, HOTPAuthentication, OTPAuthentication, IncompleteLoginSessions, \
    RecoveryCode, SecondStepVerificationConfig, WebAuthnCredential
from UserAuth.passkeys import generate_reg_options, verify_reg_response, verify_auth_response, bytes_to_str
from Users.models import User


class AuthenticationMethodsSerializer(ModelSerializer):
    is_password_available = SerializerMethodField(read_only=True)
    is_passkey_available = SerializerMethodField(read_only=True)
    social_accounts = SerializerMethodField(read_only=True)
    email = EmailField()

    class Meta:
        model = Authentication
        fields = [
            'email',
            'is_password_available',
            'is_passkey_available',
            'social_accounts',
            'default_method'
        ]
        extra_kwargs = {
            'default_method': {
                'read_only': True,
            },
        }

    def validate_email(self, value: str) -> str:
        try:
            self.instance = Authentication.objects.get(email=value)
        except Authentication.DoesNotExist:
            raise PermissionDenied(_('Email does not exist'))
        if not self.instance.user.is_active:
            raise ValidationError(_('Account is inactive'))
        return value

    @staticmethod
    def get_is_password_available(obj: Authentication):
        return obj.has_usable_password()

    @staticmethod
    def get_is_passkey_available(obj: Authentication):
        return obj.webauthn_credentials.all().exists()

    @staticmethod
    def get_social_accounts(obj: Authentication):
        return list(obj.social_authentications.all().values_list('account', flat=True))


class RegisterPasswordSerializer(ModelSerializer):
    confirm_password = CharField(write_only=True)
    password = CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'password',
            'first_name',
            'last_name',
            'confirm_password',
        ]
        extra_kwargs = {
            'password': {
                'write_only': True,
                'min_length': 8,
            },
            'first_name': {
                'required': True,
            },
            'last_name': {
                'required': True,
            }
        }

    def validate(self, attrs):
        confirm_password = attrs.pop('confirm_password')
        password = attrs.get('password')
        if password != confirm_password:
            raise ValidationError(_('Passwords not match.'))
        return attrs

    def save(self):
        password = self.validated_data.pop('password')
        email = self.validated_data.get('email')
        self.instance = User.objects.create_user(email=email, password=password)
        self.instance.authentication.default_method = DefaultAuthenticationMethod.PASSWORD_SIGNIN
        self.instance.authentication.save()
        return self.instance

    def to_representation(self, instance: User):
        return instance.authentication.auth_tokens


class BeginPasskeyRegistrationSerializer(Serializer):
    user_id = UUIDField(required=False, source='id')
    email = EmailField()
    first_name = CharField(required=True)
    last_name = CharField(required=True)

    class Meta:
        fields = (
            'id',
            'email',
            'first_name',
            'last_name',
        )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.options = None
        self.challenge = None

    def validate(self, attrs):
        user_id = attrs.pop('id', None)
        email = attrs.get('email')
        if user_id:
            try:
                self.instance = User.objects.get(pk=user_id, email=email, is_registration_completed=False)
            except User.DoesNotExist:
                raise ValidationError({
                    'id': _('User does not exist'),
                })
        else:
            try:
                User.objects.get(email=email)
                raise ValidationError({
                    'email': _('Email already in use.'),
                })
            except User.DoesNotExist:
                pass
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(is_registration_completed=False, **validated_data)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

    def save(self, **kwargs):
        instance = super().save(**kwargs)
        self.challenge, self.options = generate_reg_options(user=instance)
        return instance

    def to_representation(self, instance: User):
        data = super().to_representation(instance=instance)
        data['options'] = self.options
        return data


class CompletePasskeyRegistrationSerializer(Serializer):
    response = JSONField(required=True, write_only=True)
    userId = UUIDField(required=True, source='id')

    def __init__(self, challenge: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.verified_registration: Optional[VerifiedRegistration] = None
        self.challenge = challenge

    def validate(self, attrs: dict):
        response = attrs.get('response')
        user_id = attrs.pop('id')
        try:
            self.instance = User.objects.get(pk=user_id, is_registration_completed=False)
        except User.DoesNotExist:
            raise ValidationError({
                'id': _('User does not exist'),
            })
        try:
            self.verified_registration = verify_reg_response(response, challenge=self.challenge)
        except InvalidRegistrationResponse:
            raise ValidationError({
                'response': _('Registration failed'),
            })
        return attrs

    def save(self, **kwargs):
        self.instance.is_registration_completed = True
        WebAuthnCredential.objects.create(
            authentication=self.instance.authentication,
            credential_id=self.verified_registration.credential_id,
            credential_public_key=self.verified_registration.credential_public_key,
            sign_count=self.verified_registration.sign_count,
            credential_device_type=self.verified_registration.credential_device_type.value,
            transports=self.validated_data.get('response')['response'].get('transports'),
            credential_backed_up=self.verified_registration.credential_backed_up,
            aaguid=self.verified_registration.aaguid,
        )
        self.instance.set_unusable_password()
        self.instance.authentication.default_method = DefaultAuthenticationMethod.PASSKEY_SIGNIN
        self.instance.save(save_auth=True)
        return self.instance

    def to_representation(self, instance):
        return self.instance.authentication.auth_tokens


class CompletePasskeyAuthenticationSerializer(Serializer):
    response = JSONField(required=True)

    def __init__(self, challenge: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.challenge = challenge
        self.credential: Optional[WebAuthnCredential] = None
        self.verification: Optional[VerifiedAuthentication] = None

    def validate_response(self, response):
        credential_raw_id = response.get('rawId')
        try:
            self.credential = WebAuthnCredential.objects.get(credential_id=base64url_to_bytes(credential_raw_id))
        except WebAuthnCredential.DoesNotExist:
            raise ValidationError(_('Credential does not exist.'))
        try:
            self.verification, self.credential = verify_auth_response(
                response,
                challenge=self.challenge,
                credential=self.credential
            )
        except InvalidAuthenticationResponse as e:
            raise ValidationError(_('Authentication failed'))
        user_id_bytes = base64url_to_bytes(response['response']['userHandle'])
        user_id = bytes_to_str(user_id_bytes)
        try:
            self.instance = User.objects.get(pk=user_id, is_registration_completed=True)
        except User.DoesNotExist:
            raise ValidationError(_('User does not exist'))
        return response

    def save(self, **kwargs):
        self.credential.save()
        return self.instance

    def to_representation(self, instance):
        return self.instance.authentication.auth_tokens


class VerifyEmailOTPSerializer(Serializer):
    otp = CharField(write_only=True)

    class Meta:
        model = OTPAuthentication

    def validate_otp(self, value):
        if not self.instance:
            raise AssertionError('Pass instance to validate VerifyOTPSerializer.')
        if not self.instance.verify_otp(value):
            raise ValidationError(_('Invalid OTP.'))
        return value

    def save(self):
        auth: Authentication = self.instance.authentication
        auth.email_verified = True
        auth.save()
        user = auth.user
        user.is_active = True
        user.save()
        self.instance.delete()
        return user

    def to_representation(self, instance):
        return AuthenticatorAppSerializer(instance).data


class AuthenticatorAppSerializer(ModelSerializer):
    class Meta:
        model = HOTPAuthentication
        fields = [
            'id',
            'name',
            'is_active',
            'created_at',
            'second_step_config_id'
        ]
        extra_kwargs = {
            'is_active': {'read_only': True},
            'created_at': {'read_only': True},
            'second_step_config_id': {'read_only': True},
        }

    def validate_name(self, value):
        auth_id = self.context.get('auth_id', None)
        if auth_id is not None:
            if self.Meta.model.objects.filter(authentication_id=auth_id, name=value).exists():
                raise ValidationError(_('You already used this name.'))
        return value

    def to_representation(self, instance: HOTPAuthentication):
        data = super().to_representation(instance)
        if self.context.get('creating'):
            data['secret'] = instance.secret
        return data


class LoginSerializer(Serializer):
    incomplete_session = None
    tokens = None
    email = EmailField(
        write_only=True,
        required=True,
    )
    password = CharField(
        write_only=True,
        required=True,
    )

    class Meta:
        model = Authentication
        fields = [
            'email',
            'password'
        ]

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        try:
            auth = Authentication.objects.get(email=email)
        except Authentication.DoesNotExist:
            raise ValidationError({
                'email': _('User does not exist.')
            })
        if not (auth.email_verified and auth.user.is_active):
            raise ValidationError({
                'email': _('User is inactive.')
            })
        if not auth.check_password(password):
            raise ValidationError({
                'password': _('Password is incorrect.')
            })
        self.instance = auth
        return attrs

    def save(self):
        if self.instance.is_2fa_enabled:
            IncompleteLoginSessions.objects.filter(auth=self.instance).delete()
            self.incomplete_session = IncompleteLoginSessions.objects.create(auth=self.instance)
        else:
            self.tokens = self.instance.auth_tokens
            self.instance.user.last_login = timezone.now()
            self.instance.user.save()
        return self.instance

    def to_representation(self, instance):
        if instance.is_2fa_enabled:
            return {
                'session_id': self.incomplete_session.id
            }
        return self.tokens


class TwoFactorSettingsSerializer(ModelSerializer):
    apps = AuthenticatorAppSerializer(many=True, read_only=True, source='hotp_authentications')
    email = SerializerMethodField()

    class Meta:
        model = SecondStepVerificationConfig
        fields = [
            'is_2fa_enabled',
            'otp_2fa_enabled',
            'apps',
            'email',
            'hotp_verfication_enabled'
        ]
        extra_kwargs = {
            'is_2fa_enabled': {
                'read_only': True,
            },
            'otp_2fa_enabled': {
                'read_only': True,
            }
        }

    @staticmethod
    def get_email(instance: SecondStepVerificationConfig):
        if not (instance.otp_2fa_enabled and instance.email_verified):
            return None
        match = re.match(r"([^@]+)@(.+)", instance.email)
        if not match:
            return None
        return f"{match.group(1)[:3]}****@{match.group(2)}"


class VerifyHOTPAppSerializer(Serializer):
    otp = CharField(write_only=True)

    def validate(self, attrs):
        otp: str = attrs.get('otp')
        config: SecondStepVerificationConfig = self.instance

        if not config.is_2fa_enabled:
            raise ValidationError({
                'otp': _('2 Step Verification not enabled.')
            })

        if not config.hotp_authentications.filter(is_active=True).exists():
            raise ValidationError({
                'otp': _('Authenticator verification failed. Use any of the available method.')
            })
        if not self.verify_authenticator_app(otp):
            raise ValidationError({
                'otp': _('Authenticator verification failed. Invalid OTP')
            })
        return attrs

    def verify_authenticator_app(self, otp):
        auth: Authentication = self.instance
        for app in auth.hotp_authentications.filter(is_active=True):
            if app.verify_otp(otp, window=1):
                app.last_used = timezone.now()
                app.save()
                return True
        return False

    def save(self, **kwargs):
        IncompleteLoginSessions.objects.filter(auth_id=self.instance.authentication_id).delete()

    def to_representation(self, instance: Authentication):
        return instance.auth_tokens


class RecoverAccountSerializer(Serializer):
    recovery_code = CharField(write_only=True, required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.recovery_obj = None

    def validate_recovery_code(self, value):
        try:
            self.recovery_obj = RecoveryCode.objects.get(
                second_step_config=self.instance,
                code=value,
                is_used=False,
            )
        except RecoveryCode.DoesNotExist:
            raise ValidationError(_('Recovery code is invalid or already used.'))
        return value

    def save(self, **kwargs):
        self.recovery_obj.is_used = True
        self.recovery_obj.save()
        self.instance.is_2fa_enabled = False
        self.instance.save()
        return self.instance

    def to_representation(self, instance: SecondStepVerificationConfig):
        return instance.authentication.auth_tokens


class RecoveryCodeSerializer(ModelSerializer):
    class Meta:
        model = RecoveryCode
        fields = (
            'code',
            'is_used',
        )
        kwargs = {
            'code': {
                'read_only': True,
            },
            'is_used': {
                'read_only': True,
            }
        }


class UpdatePasswordSerializer(Serializer):
    password = CharField(required=True, write_only=True)
    new_password = CharField(required=True, write_only=True)
    confirm_password = CharField(required=True, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

        errors = {}
        if self.instance is None:
            raise AssertionError('Can\'t update password without instance.')
        if not self.instance.check_password(password):
            errors['password'] = _('Password does not valid.')
        if new_password != confirm_password:
            errors['confirm_password'] = _('Passwords do not match.')

        if errors:
            raise ValidationError(errors)
        return attrs

    def save(self, **kwargs):
        self.instance.set_password(self.validated_data.get('new_password'))
        self.instance.save()
        return self.instance


class BeginRegisterPasskeySerializer(Serializer):
    challenge = SerializerMethodField()
    user_id = CharField(read_only=True)
    username = CharField(read_only=True, source='user.email')
    display_name = CharField(read_only=True, source='user.full_name')
    exclude_credentials = SerializerMethodField()

    @staticmethod
    def get_challenge(instance: Authentication):
        return os.urandom(32)

    @staticmethod
    def get_exclude_credentials(instance: Authentication):
        return []


class ResetPasswordRequestSerializer(Serializer):
    email = EmailField(write_only=True)

    def validate_email(self, email: str):
        try:
            self.instance = User.objects.select_related('authentication').get(email=email)
        except User.DoesNotExist:
            raise ValidationError(_('User does not exist.'))
        return email

    @property
    def token(self):
        if not self.instance:
            raise AssertionError('Cannot reset password without an instance.')
        return signing.dumps({
            'user_id': str(self.instance.id),
            'created_at': timezone.now().isoformat(),
            'user_updated_at': self.instance.updated_at.isoformat()
        })

    def save(self, **kwargs):
        return self.instance, self.token


class ResetPasswordVerifySerializer(Serializer):
    token = CharField(write_only=True, required=True)
    first_name = CharField(read_only=True)
    last_name = CharField(read_only=True)
    email = EmailField(read_only=True)

    @staticmethod
    def decrypt(token: str):
        return signing.loads(token)

    def validate(self, attrs: dict):
        token = attrs.get('token')
        try:
            data = self.decrypt(token)
            created_at = datetime.fromisoformat(data.get('created_at'))
            user_updated_at = datetime.fromisoformat(data.get('user_updated_at'))
            user_id = data.get('user_id')
        except (signing.BadSignature, KeyError):
            raise ValidationError({
                'token': _('URL is invalid.'),
            })
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError({
                'token': _('URL is invalid.'),
            })
        if user.updated_at != user_updated_at:
            raise ValidationError({
                'token': _('URL expired.')
            })
        if (created_at + timedelta(minutes=30)) <= timezone.now():
            raise ValidationError({
                'token': _('URL is expired.'),
            })
        self.instance = user
        return {
            'created_at': created_at,
            'updated_at': user_updated_at,
            'user': user,
        }

    def save(self, **kwargs):
        return self.instance


class ResetPasswordSerializer(Serializer):
    password_1 = CharField(write_only=True)
    password_2 = CharField(write_only=True)

    def validate(self, attrs):
        password1 = attrs.get('password_1')
        password2 = attrs.get('password_2')
        if password1 != password2:
            raise ValidationError({
                'password1': _('Passwords do not match.'),
            })
        return attrs

    def save(self, **kwargs):
        password1 = self.validated_data.get('password_1')
        self.instance.set_password(password1)
        self.instance.save()
        return self.instance
