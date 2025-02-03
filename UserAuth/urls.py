from rest_framework.routers import DefaultRouter

from UserAuth.views import AuthenticationViewSet, SocialLoginViewSet, LoginViewSet, PasskeyViewSet, ResetPasswordViewSet

router = DefaultRouter()
router.register('', AuthenticationViewSet, basename='auth')
router.register('social-login', SocialLoginViewSet, basename='social-login')
router.register('login', LoginViewSet, basename='login')
router.register('passkey', PasskeyViewSet, basename='passkey')
router.register('reset-password', ResetPasswordViewSet, basename='reset-password')
urlpatterns = router.urls
