from django.core.mail import EmailMessage
from rest_framework.exceptions import APIException

import os
import threading


class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send(fail_silently=False)


class UtilEmail:
    @staticmethod
    def send_email(data):

        try:
            email = EmailMessage(
                subject=data['email_subject'],
                body=data['email_body'],
                from_email=os.getenv('EMAIL_FROM_MSG'),
                to=[data['email_to']])

            EmailThread(email).start()

        except Exception as e:
            raise APIException(str(e), 500)
