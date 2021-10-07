from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from .models import User
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode


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
    tokens = serializers.CharField(
        max_length=68, min_length=6, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

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
