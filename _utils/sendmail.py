from django.core.mail import EmailMessage
import os

from rest_framework.exceptions import APIException


class UtilEmail:
    @staticmethod
    def send_email(data):

        try:
            email = EmailMessage(
                subject=data['email_subject'],
                body=data['email_body'],
                from_email=os.getenv('EMAIL_FROM_MSG'),
                to=[data['email_to']])

            email.send(fail_silently=False)

        except Exception as e:
            raise APIException(str(e), 500)
