from uuid import UUID

from django.conf import settings
from django.core.mail import send_mail

from CloudCart.celery import app
from UserAuth.choices import OTPPurpose
from UserAuth.models import OTPAuthentication, HOTPAuthentication
from Users.models import User


@app.task
def generate_and_send_verification_otp(user_id: UUID):
    user: User = User.objects.get(pk=user_id)
    otp = OTPAuthentication.generate_otp(user.authentication, OTPPurpose.VERIFY_EMAIL)
    user.email_user(
        subject=f"Your OTP is {otp}",
        message=f"Your OTP is {otp}",
        from_email=settings.DEFAULT_FROM_EMAIL,
    )


@app.task
def send_reset_password_email(email: str, challenge):
    subject = "Reset Password"
    message = f"""Click here to reset your password: {challenge}"""
    send_mail(subject, message, from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[email])


@app.task
def send_2fa_otp(user_id: UUID, otp: str):
    user = User.objects.get(pk=user_id)
    user.email_user(
        subject=f"Your OTP is {otp}",
        message=f"Your OTP is {otp}",
        from_email=settings.DEFAULT_FROM_EMAIL,
    )


@app.task
def send_new_authentication_app_created_email(user_id: UUID, authenticator_id: UUID):
    user: User = User.objects.get(pk=user_id)
    authenticator: HOTPAuthentication = HOTPAuthentication.objects.get(pk=authenticator_id)
    user.email_user(
        subject="New Authentication App added to your account.",
        message=f"Your Authentication App {authenticator.name} added to your account.",
        from_email=settings.DEFAULT_FROM_EMAIL,
    )


@app.task
def send_logined_email_notification(user_id: UUID):
    user: User = User.objects.get(pk=user_id)
    user.email_user(
        subject=f"Your Login Email Notification for {str(user)}",
        message=f"Your Login Email Notification for {str(user)}",
    )


@app.task
def send_recovered_email_notification(user_id: UUID):
    user: User = User.objects.get(pk=user_id)
    user.email_user(
        subject=f"Your Recovery Email Notification for {str(user)}",
        message=f"Your Recovery Email Notification for {str(user)}",
    )
