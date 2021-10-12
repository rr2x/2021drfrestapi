from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import User
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import HttpResponsePermanentRedirect
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
import os


class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [os.getenv('APP_SCHEME'), 'http', 'https']


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=70, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        username = attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError(
                'The username should only contain alphanumeric characters')

        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=600)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=5)
    password = serializers.CharField(
        max_length=70, min_length=6, write_only=True)
    username = serializers.CharField(
        max_length=255, min_length=6, read_only=True)
    # create a method that is passed on parameter that will transform data
    # by default this will try to call get_<field_name>
    # https://www.django-rest-framework.org/api-guide/fields/#serializermethodfield
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])
        return {
            'access': user.tokens()['access'],
            'refresh': user.tokens()['refresh']
        }

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        filtered_user_by_email = User.objects.filter(email=email)

        if filtered_user_by_email and filtered_user_by_email[0].auth_provider != 'email':
            raise AuthenticationFailed(
                detail='Continue login using ' +
                filtered_user_by_email[0].auth_provider
            )

        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')

        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')

        if not user.is_verified:
            raise AuthenticationFailed('Email not verified')

        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens()
        }


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']


class ResetPasswordEmailRequestSerializer_with_redirect(serializers.Serializer):
    email = serializers.EmailField(min_length=2)
    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']


class PasswordTokenCheckAPISerializer(serializers.Serializer):
    pass  # added so that drf-yasg does not complain


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=70, min_length=6, write_only=True)
    token = serializers.CharField(min_length=1, max_length=600)
    uidb64 = serializers.CharField(min_length=1, max_length=600)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)

        except Exception as e:
            raise AuthenticationFailed(str(e), 401)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError as te:
            self.fail(str(te))
        except Exception as e:
            self.fail(str(e))
