from django.core.mail import EmailMessage
import os


class Util:
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
            print(str(e))
