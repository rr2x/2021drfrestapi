from rest_framework import status
from .test_setup import TestSetup
from ..models import User


class TestViews(TestSetup):

    def test_user_cannot_register_with_no_data(self):
        register_res = self.client.post(self.register_url)
        self.assertEqual(register_res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_can_register_correctly(self):
        register_res = self.client.post(
            self.register_url, self.user_data, format='json')
        self.assertEqual(register_res.data['email'], self.user_data['email'])
        self.assertEqual(
            register_res.data['username'], self.user_data['username'])
        self.assertEqual(register_res.status_code, status.HTTP_201_CREATED)

    def test_user_cannot_login_with_unverified_email(self):
        self.client.post(self.register_url, self.user_data, format='json')

        login_res = self.client.post(
            self.login_url, self.user_data, format='json')

        self.assertEqual(login_res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_can_login_after_verification(self):
        register_res = self.client.post(
            self.register_url, self.user_data, format='json')

        email = register_res.data['email']

        user = User.objects.get(email=email)
        user.is_verified = True
        user.save()

        login_res = self.client.post(
            self.login_url, self.user_data, format='json')

        self.assertEqual(login_res.status_code, status.HTTP_200_OK)
