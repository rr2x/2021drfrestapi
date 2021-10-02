from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView
)
from .views import RegisterView, VerifyEmail, LoginAPIView
from _utils.renderers import UtilRenderer

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register-url'),
    path('login/', LoginAPIView.as_view(), name='login-url'),
    path('email-verify/', VerifyEmail.as_view(), name='email-verify-url'),
    path('token/refresh/', TokenRefreshView.as_view(renderer_classes=(UtilRenderer,)),
         name='token_refresh-url'),
]
