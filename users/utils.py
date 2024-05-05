import datetime
import random
import string
import base64
import hashlib
import secrets
import string

from users.models import OneTimePassword, User, LogUnit
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


def log_user_action(method_name):
    def decorator(function):
        def wrapper(viewClass, request, pk=None):
            print(method_name)
            result = function(viewClass, request)
            log = LogUnit.objects.create(
                user=request.user,
                method_name=method_name
            )
            return result

        return wrapper

    return decorator


def generate_code_challenge(code_verifier):
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8').replace('=', '')
    return code_challenge


def generate_random_pass():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(20))
    return password
