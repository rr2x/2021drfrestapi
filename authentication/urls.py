from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView
)
from .views import (
    RegisterView,
    LoginAPIView,
    VerifyEmail,
    RequestPasswordResetEmail,
    PasswordTokenCheckAPI,
    SetNewPasswordAPIView
)
from _utils.renderers import UtilRenderer

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register-url'),
    path('login/', LoginAPIView.as_view(), name='login-url'),
    path('email-verify/', VerifyEmail.as_view(), name='email-verify-url'),
    path('token/refresh/', TokenRefreshView.as_view(renderer_classes=(UtilRenderer,)),
         name='token_refresh-url'),
    path('request-reset-email', RequestPasswordResetEmail.as_view(),
         name='request-reset-email-url'),
    path('password-reset/<uidb64>/<token>/',
         PasswordTokenCheckAPI.as_view(), name='password-reset-confirm-url'),
    path('password-reset-complete/',
         SetNewPasswordAPIView.as_view(), name='password-reset-complete-url'),
]
