from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from UserAuth.models import IncompleteLoginSessions
from Users.models import User


class IncompleteLoginAuthentication(BaseAuthentication):
    def authenticate(self, request):
        session_id = self.authenticate_header(request)
        if not session_id:
            return None

        try:
            session = IncompleteLoginSessions.objects.get(pk=session_id)
        except IncompleteLoginSessions.DoesNotExist:
            raise AuthenticationFailed('No Session found with this ID')

        return session.auth.user, session_id

    def authenticate_header(self, request):
        return request.session.get('incomplete_login_session_id')


class ResetPasswordAuthentication(BaseAuthentication):
    def authenticate(self, request):
        user_id = self.authenticate_header(request)
        if not user_id:
            return None

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            raise AuthenticationFailed('No User found with this ID')

        return user, user_id

    def authenticate_header(self, request):
        return request.session.get('reset_password_user_id')
