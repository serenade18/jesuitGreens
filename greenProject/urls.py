"""
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from greenApp.views import UserViewSet, UserInfoView, ChangePasswordView, TeamRolesViewSet, FarmViewSet, \
    NotificationPreferenceViewSet, NotificationsViewSet, TeamMembersViewSet, LoginViewSet, UnifiedRefreshView, \
    LeaveRequestViewSet, SalaryViewSet, SalaryPaymentViewSet, DairyCattleViewSet, MilkCollectionViewSet, \
    MapDrawingViewSet, CalvingRecordViewSet, MedicationViewSet, PoultryRecordViewSet, EggCollectionViewSet, \
    DairyGoatViewSet, GoatMilkCollectionViewSet, KiddingRecordViewSet, MortalityRecordViewSet, MilkSaleViewSet, \
    GoatMilkSaleViewSet, EggSaleViewSet

router = routers.DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'roles', TeamRolesViewSet, basename='roles')
router.register(r'team', TeamMembersViewSet, basename='team')
router.register(r'farms', FarmViewSet, basename='farms')
router.register(r'notifications', NotificationsViewSet, basename='notifications')
router.register(r'notification-prefs', NotificationPreferenceViewSet, basename='notification-prefs')
router.register(r'leave-requests', LeaveRequestViewSet, basename='leave-requests')
router.register(r'salary', SalaryViewSet, basename='salary')
router.register(r'salary-payment', SalaryPaymentViewSet, basename='salary-payment')
router.register(r'dairy-cattle', DairyCattleViewSet, basename='dairy-cattle')
router.register(r'dairy-goats', DairyGoatViewSet, basename='dairy-goats')
router.register(r'milk-collection', MilkCollectionViewSet, basename='milk-collection')
router.register(r'goat-milk', GoatMilkCollectionViewSet, basename='goat-milk')
router.register(r'map', MapDrawingViewSet, basename='map')
router.register(r'calving-records', CalvingRecordViewSet, basename="calving-records")
router.register(r'kidding-records', KiddingRecordViewSet, basename="kidding-records")
router.register(r'medications', MedicationViewSet, basename="medications")
router.register(r'birds', PoultryRecordViewSet, basename="birds")
router.register(r'egg-collections', EggCollectionViewSet, basename="egg-collections")
router.register(r"mortality", MortalityRecordViewSet, basename="mortality")
router.register(r"milk-sales", MilkSaleViewSet, basename="milk-sales")
router.register(r"goat-milk-sales", GoatMilkSaleViewSet, basename="goat-milk-sales")
router.register(r"egg-sales", EggSaleViewSet, basename="egg-sales")


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    # path('api/gettoken/', LoginViewSet.as_view({'post': 'create'}), name="gettoken"),
    # path('api/refresh_token/', UnifiedRefreshView.as_view(), name="refresh_token"),
    path('api/gettoken/', TokenObtainPairView.as_view(), name="gettoken"),
    path('api/refresh_token/', TokenRefreshView.as_view(), name="refresh_token"),
    path('api/userinfo/', UserInfoView.as_view(), name='userinfo'),
    path('api/userinfo/change-password/', ChangePasswordView.as_view(), name="change-password"),
]
