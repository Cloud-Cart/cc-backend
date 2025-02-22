import base64
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError, PermissionDenied
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import Serializer
from rest_framework.viewsets import GenericViewSet
from webauthn import generate_registration_options, options_to_json, verify_registration_response, \
    generate_authentication_options, verify_authentication_response
from webauthn.helpers import generate_challenge, parse_registration_credential_json, \
    parse_authentication_credential_json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, PublicKeyCredentialType

from UserAuth.authentications import IncompleteLoginAuthentication, ResetPasswordAuthentication
from UserAuth.choices import OTPPurpose
from UserAuth.models import OTPAuthentication, HOTPAuthentication, Authentication, RecoveryCode, WebAuthnCredential, \
    SecondStepVerificationConfig
from UserAuth.permissions import IsOwnAuthenticator
from UserAuth.serializers import RegisterSerializer, VerifyEmailOTPSerializer, AuthenticatorAppSerializer, \
    LoginSerializer, RecoveryCodeSerializer, \
    UpdatePasswordSerializer, AuthenticationMethodsSerializer, TwoFactorSettingsSerializer, VerifyHOTPAppSerializer, \
    ResetPasswordRequestSerializer, ResetPasswordVerifySerializer, ResetPasswordSerializer, RecoverAccountSerializer
from UserAuth.social_login import SocialAuthHandler
from UserAuth.tasks import send_new_authentication_app_created_email, generate_and_send_verification_otp, \
    send_2fa_otp, send_reset_password_email
from Users.models import User


def get_login_response(request: Request, auth: Authentication, ser: Serializer) -> Response:
    if not auth.is_2fa_enabled:
        return Response(ser.data)
    status_code = status.HTTP_206_PARTIAL_CONTENT
    data = ser.data
    session_id = data['session_id']
    request.session['incomplete_login_session_id'] = str(session_id)
    request.session.set_expiry(timedelta(minutes=30))
    request.session.save()
    data = {}
    return Response(data, status=status_code)


def get_challenge(request: Request):
    challenge_base64 = request.session.get('challenge')
    if not challenge_base64:
        raise ValueError("Challenge not found")
    try:
        challenge = base64.urlsafe_b64decode(challenge_base64)
    except Exception as e:
        raise ValueError(f"Error decoding challenge: {str(e)}")
    return challenge


class AuthenticationViewSet(GenericViewSet):
    @action(
        detail=False,
        methods=["POST"],
        serializer_class=RegisterSerializer
    )
    def register(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user = ser.save()
        generate_and_send_verification_otp.delay(str(user.id))
        return Response(data=ser.data, status=status.HTTP_201_CREATED)

    @action(
        detail=False,
        methods=['get'],
        url_path='b-passkey-registration',
    )
    def begin_passkey_registration(self, request, *args, **kwargs):
        user = User.objects.all().first()
        challenge = generate_challenge()
        challenge_base64 = base64.urlsafe_b64encode(challenge).decode('utf-8')
        request.session['challenge'] = challenge_base64
        request.session.save()

        options = generate_registration_options(
            rp_id="localhost",
            rp_name="Cloud Cart",
            user_name=user.first_name,
            user_id=str(user.id).encode(),
            user_display_name=f"{user.first_name} {user.last_name}",
            challenge=challenge,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(
                    id=cred.credential_id_byte,
                    type=PublicKeyCredentialType.PUBLIC_KEY if cred.type == 'public-key' else None,
                )
                for cred in user.authentication.webauthn_credentials.all()
            ]
        )
        return Response(options_to_json(options))

    @action(
        detail=False,
        methods=['post'],
        url_path='c-passkey-register',
        parser_classes=[JSONParser],
    )
    def complete_passkey_registration(self, request: Request, *args, **kwargs):
        credential = request.data

        try:
            challenge = get_challenge(request)
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.all().first()

        try:
            reg_credential = parse_registration_credential_json(credential)
        except Exception as e:
            return Response({"error": str(e)}, status=400)
        try:
            verification_result = verify_registration_response(
                credential=reg_credential,
                expected_challenge=challenge,
                expected_rp_id="localhost",  # This should match your server's RP ID
                expected_origin="http://localhost:3000",  # Update with your frontend URL
                require_user_verification=True,
            )
        except Exception as e:
            return Response({"error": f"Verification failed: {str(e)}"}, status=400)

        WebAuthnCredential.objects.create(
            authentication=user.authentication,
            credential_id=credential['id'],
            credential_id_byte=verification_result.credential_id,
            public_key=verification_result.credential_public_key,
            sign_count=verification_result.sign_count,
            type=verification_result.credential_type.value
        )

        return Response({"success": True})

    @action(
        url_path='create-hotp-authentication',
        methods=['POST'],
        serializer_class=AuthenticatorAppSerializer,
        permission_classes=[IsAuthenticated],
        detail=False
    )
    def create_hotp_authentication(self, request, *args, **kwargs):
        user: User = request.user
        serializer = self.get_serializer(
            data=request.data,
            context={'creating': True, 'auth_id': user.authentication.id}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save(authentication=user.authentication)
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    @action(
        url_path='activate-hotp-authentication',
        methods=['PATCH'],
        permission_classes=[IsOwnAuthenticator],
        detail=True,
        queryset=HOTPAuthentication.objects.all()
    )
    def activate_hotp_authentication(self, request, *args, **kwargs):
        authenticator: HOTPAuthentication = self.get_object()
        if authenticator.is_active:
            return Response(
                {
                    'error': 'Authenticator is already active',
                },
                status=status.HTTP_409_CONFLICT
            )
        ser = self.get_serializer(instance=authenticator, data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        send_new_authentication_app_created_email.delay(str(request.user.id), str(authenticator.id))
        return Response(data=ser.data, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["PATCH"],
        url_path='enable-otp-authentication',
        permission_classes=[IsAuthenticated],
    )
    def enable_otp_authentication(self, request, *args, **kwargs):
        auth: Authentication = request.user.authentication
        if auth.otp_2fa_enabled:
            return Response(
                {
                    'error': 'OTP Verification is already enabled',
                },
                status=status.HTTP_409_CONFLICT
            )

        if not auth.email_verified:
            return Response(
                {
                    'error': 'Email not verified to enable OTP authentication',
                },
                status=status.HTTP_403_FORBIDDEN
            )

        auth.otp_2fa_enabled = True
        auth.save()
        return Response(data={}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["PATCH"],
        url_path='disable-otp-authentication',
        permission_classes=[IsAuthenticated],
    )
    def disable_otp_authentication(self, request, *args, **kwargs):
        auth: Authentication = request.user.authentication
        if not auth.otp_2fa_enabled:
            return Response(
                {
                    'error': 'OTP Verification is already disabled',
                },
                status=status.HTTP_409_CONFLICT
            )
        auth.otp_2fa_enabled = False
        auth.save()
        return Response(data={}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["PATCH"],
        url_path='enable-2fa-authentication',
        permission_classes=[IsAuthenticated],
    )
    def enable_2fa_authentication(self, request, *args, **kwargs):
        auth: Authentication = request.user.authentication
        if auth.is_2fa_enabled:
            return Response(
                {
                    'error': '2FA already enabled',
                },
                status=status.HTTP_409_CONFLICT
            )
        is_authenticator_apps = auth.hotp_authentications.filter(is_active=True).exists()
        if not (is_authenticator_apps or auth.otp_2fa_enabled):
            return Response(
                {
                    'error': 'Setup OTP Verification or Authenticator before enabling 2FA authentication',
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        auth.is_2fa_enabled = True
        auth.save()
        return Response(data={}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["PATCH"],
        url_path='disable-2fa-authentication',
        permission_classes=[IsAuthenticated],
    )
    def disable_2fa_authentication(self, request, *args, **kwargs):
        auth: Authentication = request.user.authentication
        if not auth.is_2fa_enabled:
            return Response(
                {
                    'error': '2FA already disabled',
                },
                status=status.HTTP_409_CONFLICT
            )
        auth.save()
        return Response(data={}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=['GET'],
        url_path='get-recovery-codes',
        permission_classes=[IsAuthenticated],
        serializer_class=RecoveryCodeSerializer
    )
    def get_recovery_codes(self, request, *args, **kwargs):
        recovery_codes = self.request.user.authentication.recovery_codes.all()
        ser = self.get_serializer(recovery_codes, many=True)
        return Response(ser.data, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=['PUT'],
        url_path='reset-recovery-codes',
        permission_classes=[IsAuthenticated],
        serializer_class=RecoveryCodeSerializer
    )
    def reset_recovery_codes(self, request, *args, **kwargs):
        auth: Authentication = request.user.authentication
        recovery_codes = auth.recovery_codes.all()
        recovery_codes.delete()
        recovery_codes = [
            RecoveryCode.objects.create(authentication=auth)
            for _ in range(10)
        ]
        ser = self.get_serializer(recovery_codes, many=True)
        return Response(ser.data, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=['PUT'],
        url_path='update-password',
        permission_classes=[IsAuthenticated],
        serializer_class=UpdatePasswordSerializer
    )
    def update_password(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data, instance=request.user.authentication)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data, status=status.HTTP_200_OK)


class LoginViewSet(GenericViewSet):
    @action(
        detail=False,
        methods=['post'],
        permission_classes=[AllowAny],
        serializer_class=AuthenticationMethodsSerializer,
        url_path='methods'
    )
    def authentication_methods(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        return Response(data=ser.data, status=status.HTTP_200_OK)

    @action(
        detail=False,
        url_path='password',
        methods=['POST'],
        serializer_class=LoginSerializer
    )
    def login(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        auth = ser.save()
        return get_login_response(request, auth, ser)


class SecondStepLoginViewSet(GenericViewSet):
    @action(
        detail=False,
        methods=["GET"],
        url_path='2fa-methods',
        permission_classes=[IsAuthenticated],
        serializer_class=TwoFactorSettingsSerializer,
        authentication_classes=(IncompleteLoginAuthentication,)
    )
    def get_2fa_settings(self, request: Request, *args, **kwargs):
        auth = request.user.authentication
        try:
            second_config = SecondStepVerificationConfig.objects.get(authentication=auth)
            if not second_config.is_2fa_enabled:
                request.session.delete('incomplete_login_session_id')
                raise ValidationError('Second Step Verification not enabled')
        except SecondStepVerificationConfig.DoesNotExist:
            request.session.delete('incomplete_login_session_id')
            raise ValidationError('Second Step Verification not enabled')
        ser = self.get_serializer(instance=second_config)
        return Response(ser.data)

    @action(
        detail=False,
        methods=["GET"],
        url_path='request-2fa-otp',
        permission_classes=[IsAuthenticated],
        authentication_classes=(IncompleteLoginAuthentication,)
    )
    def request_2fa_otp(self, request, *args, **kwargs):
        user: User = request.user
        otp = OTPAuthentication.generate_otp(user.authentication, OTPPurpose.SECOND_STEP_VERIFICATION)
        send_2fa_otp.delay(str(user.id), otp)
        return Response(data={}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["POST"],
        serializer_class=VerifyEmailOTPSerializer,
        url_path='verify-email-otp',
        authentication_classes=(IncompleteLoginAuthentication,),
        permission_classes=[IsAuthenticated],
    )
    def verify_email_otp(self, request, *args, **kwargs):
        try:
            otp_authentication: OTPAuthentication = request.user.authentication.otp
        except OTPAuthentication.DoesNotExist:
            raise PermissionDenied('Session invalid')

        serializer = self.get_serializer(instance=otp_authentication, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        request.session.delete('incomplete_login_session_id')
        return Response(otp_authentication.authentication.auth_tokens)

    @action(
        detail=False,
        methods=["POST"],
        serializer_class=VerifyHOTPAppSerializer,
        url_path='verify-app-otp',
        authentication_classes=(IncompleteLoginAuthentication,),
        permission_classes=[IsAuthenticated],
    )
    def verify_app_otp(self, request, *args, **kwargs):
        try:
            second_step_config: SecondStepVerificationConfig = request.user.authentication.secondstep_verification
        except SecondStepVerificationConfig.DoesNotExist:
            raise PermissionDenied('Session invalid')

        serializer = self.get_serializer(instance=second_step_config, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        request.session.delete('incomplete_login_session_id')
        return Response(second_step_config.authentication.auth_tokens)

    @action(
        detail=False,
        methods=["POST"],
        url_path='recover-account',
        permission_classes=[IsAuthenticated],
        authentication_classes=(IncompleteLoginAuthentication,),
        serializer_class=RecoverAccountSerializer
    )
    def recover_account(self, request, *args, **kwargs):
        user: User = request.user
        ser = self.get_serializer(instance=user.authentication.secondstep_verification, data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        request.session.delete('incomplete_login_session_id')
        return Response(ser.data)


class PasskeyViewSet(GenericViewSet):
    @action(
        detail=False,
        methods=['get'],
        url_path='b-passkey-authentication',
        permission_classes=[AllowAny],
    )
    def begin_passkey_authentication(self, request, *args, **kwargs):
        email = request.query_params.get('email')
        allow_credentials = []
        if email:
            try:
                auth = Authentication.objects.get(user__email=email)
            except Authentication.DoesNotExist:
                raise ValidationError('Invalid email')
            else:
                allow_credentials = [
                    PublicKeyCredentialDescriptor(
                        id=cred.credential_id_byte,
                        type=PublicKeyCredentialType.PUBLIC_KEY if cred.type == 'public-key' else None,
                    )
                    for cred in auth.webauthn_credentials.all()
                ]

        challenge = generate_challenge()
        challenge_base64 = base64.urlsafe_b64encode(challenge).decode('utf-8')
        request.session['challenge'] = challenge_base64
        request.session.save()
        complex_authentication_options = generate_authentication_options(
            rp_id="localhost",
            challenge=challenge,
            allow_credentials=allow_credentials,
            timeout=12000,
        )
        return Response(options_to_json(complex_authentication_options))

    @action(
        detail=False,
        methods=['post'],
        url_path='c-passkey-authentication',
        permission_classes=[AllowAny],
        parser_classes=[JSONParser],
    )
    def complete_passkey_authentication(self, request, *args, **kwargs):
        credential = request.data
        try:
            challenge = get_challenge(request)
        except ValueError as e:
            return Response({'error': str(e)}, status=400)
        try:
            auth_credential = parse_authentication_credential_json(credential)
        except Exception as e:
            return Response({"error": str(e)}, status=400)
        try:
            web_authn = WebAuthnCredential.objects.get(credential_id=credential['id'])
        except WebAuthnCredential.DoesNotExist:
            return Response({"error": "WebAuthnCredential not found"}, status=400)
        try:
            verification_result = verify_authentication_response(
                credential=auth_credential,
                expected_challenge=challenge,
                expected_rp_id="localhost",  # This should match your server's RP ID
                expected_origin="http://localhost:3000",  # Update with your frontend URL
                require_user_verification=True,
                credential_public_key=web_authn.public_key,
                credential_current_sign_count=web_authn.sign_count
            )
        except Exception as e:
            return Response({"error": f"Verification failed: {str(e)}"}, status=400)
        web_authn.sign_count = verification_result.new_sign_count
        web_authn.save()
        auth = web_authn.authentication
        auth.user.last_login = timezone.now()
        auth.user.save()
        ser = LoginSerializer(auth)
        ser.save()
        ser = LoginSerializer(auth)
        ser.save()
        return get_login_response(request, auth, ser)


class ResetPasswordViewSet(GenericViewSet):
    @action(
        detail=False,
        methods=['post'],
        url_path='send-email',
        permission_classes=[AllowAny],
        serializer_class=ResetPasswordRequestSerializer,
    )
    def request_password_reset(self, request: Request, *args, **kwargs):
        ser: ResetPasswordRequestSerializer = self.serializer_class(data=request.data)
        ser.is_valid(raise_exception=True)
        user, token = ser.save()
        send_reset_password_email.delay(user.email, token)
        return Response(status=status.HTTP_200_OK, data={'success': True})

    @action(
        detail=False,
        methods=['post'],
        url_path='verify-challenge',
        permission_classes=[AllowAny],
        authentication_classes=[ResetPasswordAuthentication],
        serializer_class=ResetPasswordVerifySerializer,
    )
    def verify_password_reset_challenge(self, request: Request, *args, **kwargs):
        ser = self.serializer_class(data=request.data)
        ser.is_valid(raise_exception=True)
        user: User = ser.save()
        request.session['reset_password_user_id'] = str(user.id)
        request.session.set_expiry(timedelta(minutes=30))
        request.session.save()
        return Response(status=status.HTTP_200_OK, data=ser.data)

    @action(
        detail=False,
        methods=['post'],
        url_path='reset',
        permission_classes=[IsAuthenticated],
        authentication_classes=[ResetPasswordAuthentication],
        serializer_class=ResetPasswordSerializer,
    )
    def reset_password(self, request: Request, *args, **kwargs):
        ser: ResetPasswordSerializer = self.get_serializer(data=request.data, instance=request.user)
        ser.is_valid(raise_exception=True)
        ser.save()
        request.session.delete('reset_password_user_id')
        return Response(status=status.HTTP_200_OK, data=ser.data)


class SocialLoginViewSet(GenericViewSet):
    permission_classes = [AllowAny]

    @staticmethod
    def social_auth(request: Request, provider: str, code: str, redirect_uri: str):
        if not code:
            return Response({"error": "Missing code"}, status=400)

        config = {
            "google": {
                "token_url": "https://oauth2.googleapis.com/token",
                "user_info_url": None,
                "token_payload": {
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                },
            },
            "microsoft": {
                "token_url": f"https://login.microsoftonline.com/{settings.MICROSOFT_TENANT_ID}/oauth2/v2.0/token",
                "user_info_url": "https://graph.microsoft.com/v1.0/me",
                "token_payload": {
                    "client_id": settings.MICROSOFT_CLIENT_ID,
                    "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                },
            },
            "facebook": {
                "token_url": "https://graph.facebook.com/v12.0/oauth/access_token",
                "user_info_url": "https://graph.facebook.com/me?fields=id,name,email,verified",
                "token_payload": {
                    "client_id": settings.FACEBOOK_APP_ID,
                    "client_secret": settings.FACEBOOK_APP_SECRET,
                },
            },
        }

        if provider not in config:
            return Response({"error": "Invalid provider"}, status=400)

        handler = SocialAuthHandler(provider, **config[provider])
        tokens = handler.exchange_code(code, redirect_uri)
        if not tokens:
            return Response({"error": "Token exchange failed"}, status=400)

        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")

        try:
            email, name = handler.extract_user_info(access_token, id_token)
        except ValueError as e:
            return Response({"error": str(e)}, status=400)

        if not email:
            return Response({"error": "Email not found"}, status=400)

        user = handler.get_or_create_user(email, name)
        handler.create_auth()
        ser = LoginSerializer(user.authentication)
        ser.save()
        return get_login_response(request, user.authentication, ser)

    @action(methods=["post"], detail=False, url_path="google")
    def google_login(self, request, *args, **kwargs):
        return self.social_auth(request, "google", request.data.get("code"), request.data.get("redirect_uri"))

    @action(methods=["post"], detail=False, url_path="microsoft")
    def microsoft_login(self, request, *args, **kwargs):
        return self.social_auth(request, "microsoft", request.data.get("code"), request.data.get("redirect_uri"))

    @action(methods=["post"], detail=False, url_path="facebook")
    def facebook_login(self, request, *args, **kwargs):
        return self.social_auth(request, "facebook", request.data.get("code"), request.data.get("redirect_uri"))
