from django.urls import path
from .views import RegisterView, VerifyEmail, LoginAPIView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register-url'),
    path('login/', LoginAPIView.as_view(), name='login-url'),
    path('email-verify/', VerifyEmail.as_view(), name='email-verify-url'),
]
