"""
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from greenApp.views import UserViewSet, UserInfoView, ChangePasswordView, TeamRolesViewSet, FarmViewSet, \
    NotificationPreferenceViewSet

router = routers.DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'roles', TeamRolesViewSet, basename='roles')
router.register(r'farms', FarmViewSet, basename='farms')
router.register(r'notification-prefs', NotificationPreferenceViewSet, basename='notification-prefs')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/gettoken/', TokenObtainPairView.as_view(), name="gettoken"),
    path('api/refresh_token/', TokenRefreshView.as_view(), name="refresh_token"),
    path('api/userinfo/', UserInfoView.as_view(), name='userinfo'),
    path('api/userinfo/change-password/', ChangePasswordView.as_view(), name="change-password"),
]
