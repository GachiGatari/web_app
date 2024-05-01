import datetime
import random
from users.models import OneTimePassword, User


def generate_otp(otp_length=6):
    otp = "".join([str(random.randint(1, 9)) for x in range(otp_length)])
    return otp


def send_otp_to_user(email, session_id):
    otp_code = generate_otp()
    user = User.objects.get(email=email)
    try:
        otp = OneTimePassword.objects.get(user=user, session_id=session_id)
        otp.delete()
        print("Deleted")
    except OneTimePassword.DoesNotExist:
        pass

    OneTimePassword.objects.create(
        user=user,
        code=otp_code,
        session_id=session_id,
        created_at=datetime.datetime.now()
    )
    return otp_code
