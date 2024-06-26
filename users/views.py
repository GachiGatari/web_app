import random

import dotenv
import os
import requests

from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework import mixins, permissions
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.exceptions import ValidationError, NotFound
from users.serializers import (
    UserVerifySerializer,
    UserLoginSerializer,
    CustomTokenRefreshSerializer,
    PermissionSerializer,
    RoleSerializer,
    RolePermissionSerializer,
    UserRoleSerializer,
)

from users.utils import send_otp_to_user
from users.models import UserSession, User, Permission, Role, LogUnit
from rest_framework import status
from rest_framework_simplejwt.views import TokenRefreshView
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseRedirect
from rest_framework_simplejwt.tokens import RefreshToken
from django.views import View
from django.views.generic.base import RedirectView

from users.utils import check_user_permissions, log_user_action, generate_random_pass

from users.tasks import create_task
from django.http import JsonResponse

dotenv.read_dotenv()


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom Refresh token View
    """
    serializer_class = CustomTokenRefreshSerializer


class UserVerifyAPIView(APIView):
    # Note: we have to specify the following policy to allow
    # anonymous users to call this endpoint
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        # Pass user-submitted data to the serializer
        serializer = UserVerifySerializer(data=request.data)

        # Next, we trigger validation with `raise_exceptions=True`
        # which will abort the request and return user-friendly
        # error messages if the validation fails
        serializer.is_valid(raise_exception=True)
        otp_code = send_otp_to_user(serializer.data.get('email', ''), serializer.data.get('session_id', ''))

        # For now we skip any interactions with the database
        # and simply show the validated data back to the user
        return Response(otp_code, status=status.HTTP_200_OK)


class UserLoginAPIView(GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AllLogoutAPIView(APIView):
    # Note: we have to specify the following policy to allow
    # anonymous users to call this endpoint
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        session_id = request.data.get('session_id', None)
        if not session_id:
            raise ValidationError("Must provide session_id")
        try:
            UserSession.objects.get(user_id=request.user.id, session_id=session_id)
        except UserSession.DoesNotExist:
            raise NotFound("Wrong session_id")
        sessions = UserSession.objects.filter(user_id=request.user.id).exclude(session_id=session_id)
        for session in sessions:
            token = RefreshToken(session.refresh_token)
            token.blacklist()
        return Response(status=status.HTTP_200_OK)


class PermissionDetail(mixins.CreateModelMixin,
                       mixins.RetrieveModelMixin,
                       mixins.UpdateModelMixin,
                       mixins.DestroyModelMixin,
                       GenericAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

    @log_user_action("read_permission")
    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    @log_user_action("create_permission")
    @check_user_permissions(permission="can_create")
    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    @log_user_action("update_permission")
    @check_user_permissions(permission="can_update")
    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    @log_user_action("delete_permission")
    @check_user_permissions(permission="can_delete")
    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)


class RoleDetail(mixins.CreateModelMixin,
                 mixins.RetrieveModelMixin,
                 mixins.UpdateModelMixin,
                 mixins.DestroyModelMixin,
                 GenericAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    @log_user_action("read_role")
    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    @log_user_action("create_role")
    @check_user_permissions("can_create")
    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    @log_user_action("update_role")
    @check_user_permissions(permission="can_update")
    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    @log_user_action("delete_role")
    @check_user_permissions(permission="can_delete")
    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)


class RolePermissionDetail(APIView):
    serializer_class = RolePermissionSerializer
    permission_classes = [permissions.IsAdminUser]

    @log_user_action("read_role_permission")
    def get(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = get_object_or_404(Role, pk=serializer.data['role_id'])
        permissions = role.permissions.all()
        response = serializer.data
        response["permissions_list"] = PermissionSerializer(instance=permissions, many=True).data
        return Response(data=response, status=status.HTTP_200_OK)

    @log_user_action("create_role_permission")
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = get_object_or_404(Role, pk=serializer.data['role_id'])
        for perm in serializer.data["permissions_list"]:
            get_object_or_404(Permission, pk=perm)
        role.permissions.set(serializer.data["permissions_list"])
        return Response(status=status.HTTP_200_OK)

    @log_user_action("update_role_permission")
    def put(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = get_object_or_404(Role, pk=serializer.data['role_id'])
        permissions = serializer.data["permissions_list"]
        for perm in permissions:
            role.permissions.add(get_object_or_404(Permission, pk=perm).pk)
        return Response(status=status.HTTP_200_OK)

    @log_user_action("delete_role_permission")
    def delete(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = get_object_or_404(Role, pk=serializer.data['role_id'])
        permissions = serializer.data["permissions_list"]
        for perm in permissions:
            role.permissions.remove(perm)
        return Response(status=status.HTTP_200_OK)


class UserRoleDetail(APIView):
    serializer_class = UserRoleSerializer
    permission_classes = [permissions.IsAdminUser]

    @log_user_action("read_user_role")
    def get(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = get_object_or_404(User, pk=serializer.data['user_id'])
        roles = user.roles.all()
        response = serializer.data
        response["roles_list"] = RoleSerializer(instance=roles, many=True).data
        return Response(data=response, status=status.HTTP_200_OK)

    @log_user_action("create_user_role")
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = get_object_or_404(User, pk=serializer.data['user_id'])
        print(user.name)
        for role in serializer.data["roles_list"]:
            get_object_or_404(Role, pk=role)
        user.roles.set(serializer.data["roles_list"])
        return Response(status=status.HTTP_200_OK)

    @log_user_action("update_user_role")
    def put(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = get_object_or_404(User, pk=serializer.data['user_id'])
        roles = serializer.data["roles_list"]
        for role in roles:
            user.roles.add(get_object_or_404(Role, pk=role).pk)
        return Response(status=status.HTTP_200_OK)

    @log_user_action("delete_user_role")
    def delete(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = get_object_or_404(User, pk=serializer.data['user_id'])
        roles = serializer.data["roles_list"]
        for role in roles:
            user.roles.remove(role)
        return Response(status=status.HTTP_200_OK)


class OauthRedirect(View):

    def get_access_token(self, code):
        data = {
            "client_id": os.environ.get('CLIENT_ID'),
            "client_secret": os.environ.get('CLIENT_SECRET'),
            "code": code,
            "code_verifier": os.environ.get('CODE_VERIFIER'),
            "grant_type": "authorization_code",
            "redirect_uri": os.environ.get('OAUTH_REDIRECT_URL')
        }

        response = requests.post("http://host.docker.internal:8080/o/token/", data)
        return response.json()["access_token"]

    def get_user_email(self, token):
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get("http://host.docker.internal:8080/accounts/me", headers=headers)
        print(response.json())
        return response.json()["email"]

    def register_user(self, email):
        random_password = generate_random_pass()
        user = User.objects.create_user(
            email=email,
            name=email,
            password=random_password
        )
        user.from_oauth=True
        user.save()
        print(user.id, email)
        return user, random_password

    def recreate_user(self, email):
        random_password = generate_random_pass()
        user = User.objects.get(email=email)
        user.set_password(random_password)
        user.save()
        return user, random_password

    def get_token(self, email, password):
        data = {
            "email": email,
            "password": password
        }
        print(data)
        response = requests.post("http://localhost:8000/api/auth/jwt/create", data)
        return response.json()

    def register_session(self, user, token):
        session_id = random.randint(5 , 1000)
        UserSession.objects.create(
            user=user,
            session_id=session_id,
            refresh_token=str(token)
        )
        return session_id

    def get(self, request):
        code = request.GET.get('code')
        if not code:
            raise ValidationError("Invalid code")
        token = self.get_access_token(code)
        user_email = self.get_user_email(token)
        if User.objects.filter(email=user_email).exists():
            user, user_pass = self.recreate_user(user_email)
        else:
            user, user_pass = self.register_user(user_email)
        tokens_data = self.get_token(user_email, user_pass)
        print(tokens_data)
        session_id = self.register_session(user, tokens_data["access"])
        tokens_data["session_id"] = session_id
        return JsonResponse(tokens_data)
