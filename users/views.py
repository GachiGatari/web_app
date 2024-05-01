from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.exceptions import ValidationError, NotFound
# We import our serializer here
from users.serializers import UserVerifySerializer, UserLoginSerializer, CustomTokenRefreshSerializer
from users.utils import send_otp_to_user
from users.models import UserSession, User
from rest_framework import status
from rest_framework_simplejwt.views import TokenRefreshView
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from rest_framework_simplejwt.tokens import RefreshToken





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
        serializer = self.serializer_class(data=request.data, context= {'request': request})
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