from django.core.mail import EmailMessage
import os

class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject = data['email_sybject'],
            body = data['body'],
            from_email=os.environ.get('EMAIL_FROM'),
            to = [data['to_email']]
        )
        email.send()