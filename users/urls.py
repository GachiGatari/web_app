import os
import dotenv

from django.urls import path, include
from rest_framework_simplejwt.views import TokenBlacklistView
import users.views as views
from django.views.generic.base import RedirectView
from users.utils import generate_code_challenge

dotenv.read_dotenv()

urlpatterns = [
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.jwt')),
    path('auth/token/refresh/', views.CustomTokenRefreshView.as_view(), name="token_refresh"),
    path('auth/logout/', TokenBlacklistView.as_view(), name="logout"),
    path('auth/verify/', views.UserVerifyAPIView.as_view()),
    path('auth/login/', views.UserLoginAPIView.as_view()),
    path('auth/all_logout/', views.AllLogoutAPIView.as_view()),
    path('permission/<int:pk>', views.PermissionDetail.as_view()),
    path('role/<int:pk>', views.RoleDetail.as_view()),
    path('role_permission/', views.RolePermissionDetail.as_view()),
    path('user_role/', views.UserRoleDetail.as_view()),
    path('oauth/', RedirectView.as_view(
        url=f"http://localhost:8080/o/authorize/?"
            f"response_type=code&"
            f"client_id={os.environ.get('CLIENT_ID')}&"
            f"redirect_uri={os.environ.get('OAUTH_REDIRECT_URL')}&"
            f"code_challenge={generate_code_challenge(os.environ.get('CODE_VERIFIER'))}&"
            f"code_challenge_method=S256",
    )),
    path("redirect_oauth", views.OauthRedirect.as_view())
]