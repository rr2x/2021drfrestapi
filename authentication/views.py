from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.urls import reverse
from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer
from .utils import Util
import jwt

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer

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

        Util.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


# using views.APIView as special case so that api can be used on swagger
class VerifyEmail(views.APIView):

    serializer_class = EmailVerificationSerializer

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

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)
