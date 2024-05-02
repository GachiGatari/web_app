import datetime
import random
from users.models import OneTimePassword, User
from rest_framework.exceptions import PermissionDenied


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


def check_user_permissions(permission):
    def decorator(function):
        def wrapper(viewClass, request, pk=None):
            if request.user.custom_has_perm(permission):
                result = function(viewClass, request)
            else:
                raise PermissionDenied("You have no permission to do this")
            return result

        return wrapper

    return decorator
