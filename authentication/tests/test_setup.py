from faker import Faker
from rest_framework.test import APITestCase
from django.urls import reverse


class TestSetup(APITestCase):

    def setUp(self):
        self.register_url = reverse('register-url')
        self.login_url = reverse('login-url')

        self.fake = Faker()

        self.user_data = {
            'email': self.fake.email(),
            'username': self.fake.email().split('@')[0],
            'password': self.fake.email(),
        }

        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()
