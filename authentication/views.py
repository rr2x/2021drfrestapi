from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.urls import reverse
from django.utils.encoding import DjangoUnicodeDecodeError, smart_bytes, smart_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from _utils.renderers import UtilRenderer

from .models import User
from .serializers import (
    RegisterSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    ResetPasswordEmailRequestSerializer,
    PasswordTokenCheckAPISerializer,
    SetNewPasswordSerializer,
    LogoutSerializer
)
from _utils.sendmail import UtilEmail
import jwt

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UtilRenderer,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)  # execute validate()
        serializer.save()  # execute create()

        user_data = serializer.data

        # returns User object from database
        user = User.objects.get(email=user_data['email'])

        # for_user() extracts user.id as reference (defined on payload as user_id) then creates token
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify-url')

        absurl = 'http://' + current_site + \
            relativeLink + '?token=' + str(token)

        email_body = 'Hi ' + user.username + \
            ' use link below to verify your email \n' + absurl

        data = {'email_body': email_body,
                'email_subject': 'verify email',
                'email_to': user_data['email']}

        UtilEmail.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


# using views.APIView as special case so that api can be used on swagger
class VerifyEmail(views.APIView):

    serializer_class = EmailVerificationSerializer
    renderer_classes = (UtilRenderer,)

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='the token used for activation', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')

        try:
            # involved payload attributes: token_type, exp, jti, user_id
            payload = jwt.decode(
                jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])

            user = User.objects.get(id=payload['user_id'])

            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as j:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError as d:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer
    renderer_classes = (UtilRenderer,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):

    serializer_class = ResetPasswordEmailRequestSerializer
    renderer_classes = (UtilRenderer,)

    def post(self, request):

        email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)

            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))

            token = PasswordResetTokenGenerator().make_token(user)

            current_site = get_current_site(
                request=request).domain

            relativeLink = reverse(
                'password-reset-confirm-url', kwargs={'uidb64': uidb64, 'token': token})

            absurl = 'http://' + current_site + relativeLink

            email_body = 'Hello, \n Use link below to reset password \n' + absurl

            data = {'email_body': email_body,
                    'email_subject': 'reset password',
                    'email_to': email}

            # send a token that will be used to reset password
            UtilEmail.send_email(data=data)

        # still execute, so that nobody can try to guess existing email accounts
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):

    serializer_class = PasswordTokenCheckAPISerializer
    renderer_classes = (UtilRenderer,)

    # verify received token for reset password
    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Invalid token, request a new one'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success': 'true', 'message': 'credentials valid', 'uidb64': uidb64, 'token': token})

        except DjangoUnicodeDecodeError:
            return Response({'error': 'Invalid token, request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)})


class SetNewPasswordAPIView(generics.GenericAPIView):

    serializer_class = SetNewPasswordSerializer
    renderer_classes = (UtilRenderer,)

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': 'true', 'message': 'password successfully reset'}, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):

    serializer_class = LogoutSerializer
    renderer_classes = (UtilRenderer,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"message": "no-content"}, status=status.HTTP_204_NO_CONTENT)
