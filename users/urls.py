from django.urls import path, include
from rest_framework_simplejwt.views import TokenBlacklistView
import users.views as views


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
]