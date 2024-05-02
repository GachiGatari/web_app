import datetime

from djoser.serializers import UserCreateSerializer, UserSerializer
from users.models import User, OneTimePassword, UserSession, Permission, Role
from rest_framework import serializers
from django.contrib.auth import authenticate
import os
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.state import token_backend


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    session_id = serializers.CharField(write_only=True)

    def validate(self, attrs):
        request = self.context.get('request')

        session_id = attrs.get("session_id", None)
        if not session_id:
            raise serializers.ValidationError(
                "Must have session_id"
            )

        data = super(CustomTokenRefreshSerializer, self).validate(attrs)
        print("Refresh Data", data)
        decoded_payload = token_backend.decode(data['access'], verify=True)
        user_uid = decoded_payload['user_id']
        try:
            user_session = UserSession.objects.get(user_id=user_uid, session_id=session_id)
        except UserSession.DoesNotExist:
            raise serializers.ValidationError(
                "Wrong session_id"
            )
        user_session.refresh_token = data.get("refresh")
        user_session.save()

        return data


class UserCreateSerializer(UserCreateSerializer):
    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = ('id', 'email', 'name', 'password')


class UserVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    session_id = serializers.CharField()

    def validate(self, attrs):
        # Here we don't need to check whether a user with the given
        # email or username exists, as this would have already
        # been done by the one of our `validate_...` methods
        email, password = attrs.get('email', None), attrs.get('password', None)
        if not email and not password:
            raise serializers.ValidationError(
                'Either an email and password must be provided.'
            )

        user = authenticate(email=email, password=password)
        print(user)
        if not user:
            raise serializers.ValidationError(
                'Wrong email or password'
            )

        return attrs


class UserLoginSerializer(serializers.Serializer):
    otp_code = serializers.CharField()
    session_id = serializers.CharField()
    msg_for_user = serializers.CharField(max_length=255, read_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, attrs):
        max_count_codes = int(os.environ.get("MAX_OTP_FOR_USER"))
        otp_lifetime = float(os.environ.get("OTP_LIFETINE"))
        msg_for_user = ""
        try:
            otp = OneTimePassword.objects.get(code=attrs.get("otp_code"))
        except OneTimePassword.DoesNotExist:
            raise serializers.ValidationError(
                "No such otp code"
            )

        if otp.session_id != attrs.get("session_id"):
            raise serializers.ValidationError(
                "Wrong device for this code"
            )

        if datetime.datetime.now(datetime.timezone.utc) - otp.created_at > datetime.timedelta(minutes=otp_lifetime):
            raise serializers.ValidationError(
                "Expired otp code"
            )
        user = otp.user
        users_codes = OneTimePassword.objects.filter(user=user)
        print(f"Колво кодов: {len(users_codes)}")
        msg_for_user = f"You have more than {max_count_codes} login device, please log out on all of them" \
            if len(users_codes) > max_count_codes \
            else "You have successfully logged in"

        refresh = RefreshToken.for_user(user)
        try:
            user_session = UserSession.objects.get(
                user=user,
                session_id=otp.session_id
            )
            user_session.refresh_token = str(refresh)
            user_session.save()
        except UserSession.DoesNotExist:
            UserSession.objects.create(
                user=user,
                session_id=otp.session_id,
                refresh_token=str(refresh)
            )
        otp.delete()

        return {
            "otp_code": attrs.get("otp_code"),
            "session_id": attrs.get("session_id"),
            "msg_for_user": msg_for_user,
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh)
        }


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name']


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'name', 'permissions']
        extra_kwargs = {'permissions': {'allow_empty': True}}


class RolePermissionSerializer(serializers.Serializer):
    role_id = serializers.IntegerField()
    permissions_list = serializers.ListField(required=False, default=[])

class UserRoleSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    roles_list = serializers.ListField(required=False, default=[])
