from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from UserAuth.views import AuthenticationViewSet, LoginViewSet, ResetPasswordViewSet, SecondStepLoginViewSet, \
    RegisterViewSet

router = DefaultRouter()
router.register('', AuthenticationViewSet, basename='auth')
router.register('login', LoginViewSet, basename='login')
router.register('reset-password', ResetPasswordViewSet, basename='reset-password')
router.register('second-step', SecondStepLoginViewSet, basename='second-step')
router.register('register', RegisterViewSet, basename='register')
urlpatterns = router.urls
urlpatterns += [
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh')
]
