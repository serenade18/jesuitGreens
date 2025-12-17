import jwt
from datetime import datetime, timedelta

from django.contrib.auth.hashers import make_password, check_password
from django.db import models
from django.db.models.functions import TruncMonth
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.utils.timezone import now
from rest_framework import viewsets, status
from rest_framework.exceptions import ValidationError, PermissionDenied, AuthenticationFailed
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated, AllowAny, BasePermission
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from jwt import ExpiredSignatureError, InvalidTokenError
from django.utils.dateparse import parse_date
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from django.db.models import Sum, Avg
from collections import defaultdict

from greenProject import settings
from greenApp.models import UserAccount, TeamRoles, Farm, NotificationPreference, Notification, TeamMember, \
    LeaveRequest, Salary, SalaryPayment, DairyCattle, MilkCollection, MapDrawing, CalvingRecord, Medication, \
    PoultryBatch, EggCollection, DairyGoat, GoatMilkCollection, KiddingRecord, MortalityRecord, MilkSale, GoatMilkSale, \
    EggSale, Customers, Orders, Expense, RecurringExpense, Tasks, BillPayment, Procurement, Inventory, Rabbit, Pond, \
    CatfishBatch, CatfishSale, FeedingSchedule, FeedingRecord, DairyCattleFeedingSchedule, DairyCattleFeedingRecord, \
    DairyGoatFeedingSchedule, DairyGoatFeedingRecord, MpesaPayment, FarmVisitBooking, BirdsFeedingSchedule, \
    BirdsFeedingRecord, FarmPlants, Plot, CropPlanting, CropHarvest, IrrigationSchedule, FertilizerApplication, \
    PesticideApplication

from greenApp.permissions import IsAdminRole, IsFarmManagerRole, IsTeamMemberRole

from greenApp.serializers import UserAccountSerializer, UserCreateSerializer, TeamRolesSerializer, FarmSerializer, \
    NotificationPreferenceSerializer, NotificationSerializer, TeamSerializer, LeaveRequestSerializer, SalarySerializer, \
    SalaryDetailSerializer, SalaryPaymentSerializer, DairyCattleSerializer, MilkCollectionSerializer, \
    MapDrawingSerializer, CalvingRecordSerializer, MedicationSerializer, PoultryRecordSerializer, \
    EggCollectionSerializer, DairyGoatSerializer, GoatMilkCollectionSerializer, KiddingRecordSerializer, \
    MortalityRecordSerializer, MilkSaleSerializer, GoatMilkSaleSerializer, EggSaleSerializer, CustomerSerializer, \
    OrdersSerializer, ExpenseSerializer, RecurringExpenseSerializer, TaskSerializer, BillPaymentSerializer, \
    ProcurementSerializer, InventorySerializer, RabbitSerializer, PondSerializer, CatfishSerializer, \
    CatfishSaleSerializer, FeedingScheduleSerializer, FeedingRecordSerializer, DairyCattleFeedingScheduleSerializer, \
    DairyCattleFeedingRecordSerializer, DairyGoatFeedingScheduleSerializer, DairyGoatFeedingRecordSerializer, \
    MpesaPaymentSerializer, BookingsSerializer, BirdsFeedingScheduleSerializer, BirdsFeedingRecordSerializer, \
    FarmPlantsSerializer, PlotSerializer, CropPlantingSerializer, CropHarvestSerializer, IrrigationScheduleSerializer, \
    FertilizerApplicationSerializer, PesticideApplicationSerializer

from .services import MpesaService


# Create your views here.

def encode_manual_token(payload: dict, lifetime: timedelta, algorithm="HS256") -> str:
    now = datetime.utcnow()
    token_payload = payload.copy()
    token_payload["iat"] = int(now.timestamp())
    token_payload["exp"] = int((now + lifetime).timestamp())
    token = jwt.encode(token_payload, settings.SECRET_KEY, algorithm=algorithm)
    return token if isinstance(token, str) else token.decode("utf-8")


def decode_manual_token(token: str, verify_exp=True) -> dict:
    """Decode a manual TeamMember JWT"""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"], options={"verify_exp": verify_exp})
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Manual token expired")
    except jwt.InvalidTokenError:
        raise AuthenticationFailed("Invalid manual token")


def decode_team_member_token(token: str):
    try:
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        if decoded.get("user_type") != "team_member":
            raise AuthenticationFailed("Token is not for a team member")
        team_member = TeamMember.objects.get(id=decoded["id"], is_active=True)
        return team_member, "team_member"
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Team member token expired")
    except jwt.InvalidTokenError:
        raise AuthenticationFailed("Invalid team member token")
    except TeamMember.DoesNotExist:
        raise AuthenticationFailed("Team member not found")


# Decode UserAccount via SimpleJWT
def decode_user_account_token(token: str):
    jwt_auth = JWTAuthentication()
    try:
        validated_token = jwt_auth.get_validated_token(token)
        user = jwt_auth.get_user(validated_token)
        return user, "user_account"
    except Exception:
        raise AuthenticationFailed("Invalid UserAccount token")


# Unified get_authenticated_user
def get_authenticated_user(request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise AuthenticationFailed("Missing or invalid authorization header")

    token = auth_header.split(" ")[1]

    # Try TeamMember first
    try:
        return decode_team_member_token(token)
    except AuthenticationFailed:
        # Not a TeamMember token, fallback to UserAccount
        return decode_user_account_token(token)


# --- Login ---
class LoginViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        if not email or not password:
            return Response({"error": True, "message": "Email and password are required"},
                            status=status.HTTP_400_BAD_REQUEST)

        #  UserAccount login
        try:
            user = UserAccount.objects.get(email=email)
            if user.check_password(password):
                token = RefreshToken.for_user(user)
                return Response({
                    "access": str(token.access_token),
                    "refresh": str(token),
                }, status=status.HTTP_200_OK)
        except UserAccount.DoesNotExist:
            pass

        #  TeamMember login
        try:
            team_member = TeamMember.objects.get(email=email, is_active=True)
            if check_password(password, team_member.password):
                access_payload = {"id": team_member.id, "email": team_member.email, "user_type": "team_member"}
                refresh_payload = {"id": team_member.id, "email": team_member.email,
                                   "user_type": "team_member", "type": "refresh"}

                access_token = encode_manual_token(access_payload, timedelta(hours=1))
                refresh_token = encode_manual_token(refresh_payload, timedelta(days=7))
                return Response({"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK)
        except TeamMember.DoesNotExist:
            pass

        return Response({"error": True, "message": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)


# --- Refresh ---
class UnifiedRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"error": True, "message": "Refresh token is required"}, status=400)

        # SimpleJWT refresh
        try:
            token = RefreshToken(refresh_token)
            return Response({"access": str(token.access_token)}, status=status.HTTP_200_OK)
        except Exception:
            pass

        # Manual TeamMember refresh
        try:
            decoded = decode_manual_token(refresh_token)
            if decoded.get("user_type") == "team_member" and decoded.get("type") == "refresh":
                new_access_token = encode_manual_token(
                    {"id": decoded["id"], "email": decoded["email"], "user_type": "team_member"},
                    timedelta(hours=1)
                )
                return Response({"access": new_access_token}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": True, "message": str(e)}, status=401)

        return Response({"error": True, "message": "Invalid or unsupported refresh token"}, status=400)


# --- User Info ---
class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserAccountSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        """Full update of logged-in user's profile"""
        user = request.user
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            # Handle password hashing if updated
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        """Partial update of logged-in user's profile"""
        user = request.user
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        """Allow logged-in user to delete their own account"""
        user = request.user
        user.delete()
        return Response({"message": "Account deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not current_password or not new_password:
            return Response(
                {"error": "Both current_password and new_password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not user.check_password(current_password):
            return Response(
                {"error": "Current password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(new_password)
        user.save()

        return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)


class UserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [AllowAny],
        'list': [IsAdminRole],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        try:
            users = UserAccount.objects.all()
            serializer = UserAccountSerializer(users, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Users List Data", "data": response_data}
        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(
            response_dict,
            status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK
        )

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Directly activate the user
            serializer.validated_data['is_active'] = True
            serializer.save()

            return Response(
                {"message": "User account created successfully"},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)

        # Permission check
        if request.user.role != "super_admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only update your own account.")

        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            # Handle password hashing if updated
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)

        # Permission check
        if request.user.role != "super_admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only update your own account.")

        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)

        # Permission check
        if request.user.role != "super_admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only delete your own account.")

        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
# --- User Info ---


# Team roles
class TeamRolesViewSet(viewsets.ModelViewSet):
    permission_classes_by_action = {
        'create': [IsFarmManagerRole, IsAdminRole],
        'list': [AllowAny],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])
        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            roles = TeamRoles.objects.all().order_by('-id')
            serializer = TeamRolesSerializer(roles, many=True)
            return Response({
                "error": False,
                "message": "All Roles Data",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = TeamRolesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Role created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        role = get_object_or_404(TeamRoles, pk=pk)
        serializer = TeamRolesSerializer(role)
        return Response({
            "error": False,
            "message": "Role retrieved successfully",
            "data": serializer.data
        })

    def update(self, request, pk=None):
        try:
            role = get_object_or_404(TeamRoles, pk=pk)
            serializer = TeamRolesSerializer(role, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Role updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            role = get_object_or_404(TeamRoles, pk=pk)
            role.delete()
            return Response({
                "error": False,
                "message": "Role deleted successfully"
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Farm settings
class FarmViewSet(viewsets.ModelViewSet):
    permission_classes_by_action = {
        'create': [IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'retrieve': [IsFarmManagerRole, IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])
        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            user = request.user

            if IsAdminRole().has_permission(request, self):
                farm = Farm.objects.all().order_by("-id")
            else:
                farm = Farm.objects.filter(user_id=user).order_by("-id")
            serializer = FarmSerializer(farm, many=True)
            return Response({
                "error": False,
                "message": "All farms Data",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        serializer = FarmSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user_id=request.user)
            return Response({
                "error": False,
                "message": "Farm created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        farm = get_object_or_404(Farm, pk=pk)
        serializer = FarmSerializer(farm)
        return Response({
            "error": False,
            "message": "Farm retrieved successfully",
            "data": serializer.data
        })

    def update(self, request, pk=None):
        try:
            farm = get_object_or_404(Farm, pk=pk)
            serializer = FarmSerializer(farm, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Farm updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            farm = get_object_or_404(Farm, pk=pk)
            farm.delete()
            return Response({
                "error": False,
                "message": "Farm deleted successfully"
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Notifications settings
class NotificationPreferenceViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        try:
            prefs, _ = NotificationPreference.objects.get_or_create(user=request.user)
            serializer = NotificationPreferenceSerializer(prefs)
            return Response({
                "error": False,
                "message": "Notification preferences retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["patch", "put"], url_path="update")
    def update_preferences(self, request):
        prefs, _ = NotificationPreference.objects.get_or_create(user=request.user)
        serializer = NotificationPreferenceSerializer(prefs, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Notifications updated",
                "data": serializer.data
            })
        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# Notifications
class NotificationsViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        filter_param = request.query_params.get("filter", "all")
        
        notice = Notification.objects.all()
        if filter_param == "unread":
            notice = notice.filter(read=False)

        notice = notice.order_by("-added_on")
        serializer = NotificationSerializer(notice, many=True)

        return Response({
            "error": False,
            "message": "Notifications retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        try:
            notice = Notification.objects.get(pk=pk, user=request.user)
            serializer = NotificationSerializer(notice)
            return Response({
                "error": False,
                "message": "Notification retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({
                "error": True,
                "message": "Notification not found"
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=["post"])
    def mark_as_read(self, request, pk=None):
        try:
            notice = Notification.objects.get(pk=pk, user=request.user)
            notice.read = True
            notice.save()
            serializer = NotificationSerializer(notice)
            return Response({
                "error": False,
                "message": "Notification marked as read",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({
                "error": True,
                "message": "Notification not found"
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=["post"])
    def mark_all_as_read(self, request):
        updated_count = Notification.objects.filter(user=request.user, read=False).update(read=True)
        return Response({
            "error": False,
            "message": f"{updated_count} notifications marked as read"
        }, status=status.HTTP_200_OK)

    def destroy(self, request, pk=None):
        try:
            notice = Notification.objects.get(pk=pk, user=request.user)
            notice.delete()
            return Response({
                "error": False,
                "message": "Notification deleted successfully"
            }, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({
                "error": True,
                "message": "Notification not found"
            }, status=status.HTTP_404_NOT_FOUND)


# Team Members
class TeamMembersViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'retrieve': [IsFarmManagerRole, IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            user = request.user
            if IsAdminRole().has_permission(request, self):
                team = TeamMember.objects.all().order_by("-id")
            else:
                team = TeamMember.objects.filter(user=user).order_by("-id")
            serializer = TeamSerializer(team, many=True)
            return Response({
                "error": False,
                "message": "All Team Members",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        try:
            data = request.data.copy()
            data['user'] = request.user.id  # link to the farm admin creating the member

            if 'password' in data and data['password']:
                raw_password = data['password']
                data['password'] = make_password(raw_password)  # hash password
            else:
                return Response({
                    "error": True,
                    "message": "Password is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer = TeamSerializer(data=data)
            if serializer.is_valid():
                team_member = serializer.save()

                # Create corresponding UserAccount
                user_account, created = UserAccount.objects.get_or_create(
                    email=team_member.email,
                    name=team_member.name,
                    phone=team_member.phone,
                    defaults={
                        "password": make_password(request.data["password"]),
                        "role": "farm_worker",
                    }
                )

                return Response({
                    "error": False,
                    "message": "Team Member Created Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "error": True,
                "message": "Validation Failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            member = TeamMember.objects.get(pk=pk)
            serializer = TeamSerializer(member)
            return Response({
                "error": False,
                "message": "Team Member Details",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except TeamMember.DoesNotExist:
            return Response({
                "error": True,
                "message": "Team Member Not Found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            member = TeamMember.objects.get(pk=pk)
            data = request.data.copy()
            if 'password' in data and data['password']:
                data['password'] = make_password(data['password'])
            serializer = TeamSerializer(member, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Team Member Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": True,
                    "message": "Validation Failed",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except TeamMember.DoesNotExist:
            return Response({
                "error": True,
                "message": "Team Member Not Found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            member = TeamMember.objects.get(pk=pk)

            # Delete corresponding UserAccount (if it exists)
            UserAccount.objects.filter(email=member.email).delete()

            member.delete()
            return Response({
                "error": False,
                "message": "Team Member Deleted Successfully"
            }, status=status.HTTP_200_OK)

        except TeamMember.DoesNotExist:
            return Response({
                "error": True,
                "message": "Team Member Not Found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Leave requests
class LeaveRequestViewSet(viewsets.ModelViewSet):
    serializer_class = LeaveRequestSerializer

    permission_classes_by_action = {
        'create': [IsFarmManagerRole, IsAdminRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'retrieve': [IsFarmManagerRole, IsAdminRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def get_queryset(self):
        user = self.request.user
        if IsAdminRole().has_permission(self.request, self):
            # Admin sees all leave requests
            return LeaveRequest.objects.all().order_by("-id")
        elif IsFarmManagerRole().has_permission(self.request, self):
            # Farm Admin sees all leaves of their associated team members
            return LeaveRequest.objects.filter(team_member__user=user).order_by("-id")
        else:
            # Regular team member sees only their own leaves
            return LeaveRequest.objects.filter(team_member__user=user, team_member__email=user.email).order_by("-id")

    def list(self, request, *args, **kwargs):
        try:
            leaves = self.get_queryset()
            serializer = LeaveRequestSerializer(leaves, many=True)
            return Response({
                "error": False,
                "message": "All Leave Requests",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        try:
            user = request.user

            # Find matching team member
            try:
                team_member = TeamMember.objects.get(email=user.email)
            except TeamMember.DoesNotExist:
                return Response({
                    "error": True,
                    "message": "Team member record not found for this user.",
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            start_date = serializer.validated_data["start_date"]
            end_date = serializer.validated_data["end_date"]

            if start_date > end_date:
                return Response({
                    "error": True,
                    "message": "End date cannot be earlier than start date.",
                }, status=status.HTTP_400_BAD_REQUEST)

            # Prevent overlapping leave requests
            overlap = LeaveRequest.objects.filter(
                team_member=team_member,
                start_date__lte=end_date,
                end_date__gte=start_date
            ).exists()

            if overlap:
                return Response({
                    "error": True,
                    "message": "You already have a leave request in this date range.",
                }, status=status.HTTP_400_BAD_REQUEST)

            # Calculate days
            days = (end_date - start_date).days + 1

            # Create leave request
            leave = LeaveRequest.objects.create(
                team_member=team_member,
                leave_type=serializer.validated_data["leave_type"],
                start_date=start_date,
                end_date=end_date,
                days=days,
                status="Pending",
            )

            # CREATE NOTIFICATION
            Notification.objects.create(
                user=user,
                title="Leave Request Submitted",
                message=f"Leave request for {start_date} to {end_date} ({days} days) has been submitted successfully.",
                type="success",
                category="team"
            )

            return Response({
                "error": False,
                "message": "Leave Request Created",
                "data": LeaveRequestSerializer(leave).data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, *args, **kwargs):
        try:
            leave = self.get_object()
            serializer = self.get_serializer(leave)
            return Response({
                "error": False,
                "message": "Leave Request Details",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        try:
            leave = self.get_object()
            serializer = self.get_serializer(leave, data=request.data, partial=False)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({
                "error": False,
                "message": "Leave Request Updated",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, **kwargs):
        try:
            leave = self.get_object()
            serializer = self.get_serializer(leave, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({
                "error": False,
                "message": "Leave Request Partially Updated",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            leave = self.get_object()
            leave.delete()
            return Response({
                "error": False,
                "message": "Leave Request Deleted",
                "data": None
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["patch"], url_path="approve", permission_classes=[IsFarmManagerRole, IsAdminRole])
    def approve(self, request, pk=None):
        try:
            leave = self.get_object()
            leave.status = "Approved"
            leave.save()
            serializer = self.get_serializer(leave)
            return Response({
                "error": False,
                "message": "Leave Request Approved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not approve leave",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["patch"], url_path="reject", permission_classes=[IsFarmManagerRole, IsAdminRole])
    def reject(self, request, pk=None):
        try:
            leave = self.get_object()
            leave.status = "Rejected"
            leave.save()
            serializer = self.get_serializer(leave)
            return Response({
                "error": False,
                "message": "Leave Request Rejected",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not reject leave",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Salaries
class SalaryViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole],
        'retrieve': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'partial_update': [IsFarmManagerRole, IsAdminRole],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            user = request.user
            if IsAdminRole().has_permission(request, self):
                salaries = Salary.objects.all().order_by("-id")
            else:
                salaries = Salary.objects.filter(employee__user=user).order_by("-id")

            serializer = SalarySerializer(salaries, many=True)
            return Response({
                "error": False,
                "message": "All Salaries",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            salary = get_object_or_404(Salary, pk=pk)
            serializer = SalaryDetailSerializer(salary)
            return Response({
                "error": False,
                "message": "Salary Details",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        try:
            member_id = request.data.get("employee")
            if not member_id:
                return Response({
                    "error": True,
                    "message": "Team member is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get the member
            member = get_object_or_404(TeamMember, id=member_id)

            # Get the role name from Role model
            if not member.role:
                return Response({
                    "error": True,
                    "message": "Selected team member has no role assigned"
                }, status=status.HTTP_400_BAD_REQUEST)

            role_name = member.role.role_name  # <-- Fetch role_name via role ID

            # Inject into request data
            data = request.data.copy()
            data["role"] = role_name  # <-- Save role name in salary

            serializer = SalarySerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Salary Created Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "error": True,
                "message": "Validation Failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            salary = get_object_or_404(Salary, pk=pk)
            serializer = SalarySerializer(salary, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Salary Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation Failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            salary = get_object_or_404(Salary, pk=pk)
            salary.delete()
            return Response({
                "error": False,
                "message": "Salary Deleted Successfully"
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Salary Payment
class SalaryPaymentViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsFarmManagerRole, IsAdminRole, IsTeamMemberRole],
        'update': [IsFarmManagerRole, IsAdminRole, IsTeamMemberRole],
        'partial_update': [IsFarmManagerRole, IsAdminRole, IsTeamMemberRole],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action["default"])

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            user = request.user

            if IsAdminRole().has_permission(request, self):
                payments = SalaryPayment.objects.all()
            else:
                payments = SalaryPayment.objects.filter(salary__employee__user=user)

            serializer = SalaryPaymentSerializer(payments, many=True)
            return Response({
                "error": False,
                "message": "Salary Payments Retrieved",
                "data": serializer.data
            })

        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not retrieve salary payments",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        try:
            salary_id = request.data.get("salary")
            if not salary_id:
                return Response({
                    "error": True,
                    "message": "Salary ID is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            salary = get_object_or_404(Salary, id=salary_id)

            serializer = SalaryPaymentSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Salary Payment Recorded Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "error": True,
                "message": "Validation Failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not create salary payment",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            payment = get_object_or_404(SalaryPayment, id=pk)
            serializer = SalaryPaymentSerializer(payment)
            return Response({
                "error": False,
                "message": "Salary Payment Retrieved",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not retrieve salary payment",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            payment = get_object_or_404(SalaryPayment, id=pk)
            serializer = SalaryPaymentSerializer(payment, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Salary Payment Updated Successfully",
                    "data": serializer.data
                })
            return Response({
                "error": True,
                "message": "Validation Failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not update salary payment",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            payment = get_object_or_404(SalaryPayment, id=pk)
            serializer = SalaryPaymentSerializer(payment, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Salary Payment Partially Updated",
                    "data": serializer.data
                })
            return Response({
                "error": True,
                "message": "Validation Failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not update salary payment",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            payment = get_object_or_404(SalaryPayment, id=pk)
            payment.delete()
            return Response({
                "error": False,
                "message": "Salary Payment Deleted Successfully"
            })
        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not delete salary payment",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["post"])
    def process_payroll(self, request):
        try:
            salaries = Salary.objects.filter(status__iexact="Pending")

            processed = []

            for salary in salaries:
                payment = SalaryPayment.objects.create(
                    salary=salary,
                    amount=salary.monthly_salary,
                    method="CASH",  # or MPESA if you want
                    reference=f"PAY-{timezone.now().timestamp()}",
                    success=True,
                )

                salary.status = "Paid"
                salary.last_paid = timezone.now().date()
                salary.save()

                processed.append({
                    "salary_id": salary.id,
                    "employee": salary.employee.name,
                    "amount": str(payment.amount),
                    "date": payment.date,
                })

            return Response({
                "error": False,
                "message": "Payroll processed successfully",
                "data": processed
            }, status=200)

        except Exception as e:
            return Response({
                "error": True,
                "message": "Failed to process payroll",
                "details": str(e)
            }, status=400)


# Dairy cattle
class DairyCattleViewSet(viewsets.ModelViewSet):
    queryset = DairyCattle.objects.all().order_by('-id')
    serializer_class = DairyCattleSerializer
    permission_classes = [IsAuthenticated]     # Override per action if needed

    # ---- Filters, search, ordering ----
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['breed', 'category', 'animal_type']
    search_fields = ['animal_name', 'tag_number', 'breed', 'category']
    ordering_fields = ['created_at', 'date_of_birth', 'animal_name']
    # ---- Standard response wrapper ----
    def response(self, error, message, data=None, status_code=status.HTTP_200_OK):
        return Response({
            "error": error,
            "message": message,
            "data": data
        }, status=status_code)

    # ---- CREATE ----
    def create(self, request, *args, **kwargs):
        serializer = DairyCattleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.response(False, "Cattle added successfully", serializer.data, status.HTTP_201_CREATED)
        return self.response(True, "Validation Error", serializer.errors, status.HTTP_400_BAD_REQUEST)

    # ---- LIST ----
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = DairyCattleSerializer(queryset, many=True)
        return self.response(False, "Cattle list fetched", serializer.data)

    # ---- RETRIEVE ----
    def retrieve(self, request, pk=None, *args, **kwargs):
        cattle = self.get_object()
        serializer = DairyCattleSerializer(cattle)
        return self.response(False, "Cattle details fetched", serializer.data)

    # ---- UPDATE ----
    def update(self, request, *args, **kwargs):
        cattle = self.get_object()
        serializer = DairyCattleSerializer(cattle, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.response(False, "Cattle updated successfully", serializer.data)
        return self.response(True, "Validation Error", serializer.errors, status.HTTP_400_BAD_REQUEST)

    # ---- PARTIAL UPDATE ----
    def partial_update(self, request, *args, **kwargs):
        cattle = self.get_object()
        serializer = DairyCattleSerializer(cattle, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return self.response(False, "Cattle updated successfully", serializer.data)
        return self.response(True, "Validation Error", serializer.errors, status.HTTP_400_BAD_REQUEST)

    # ---- DELETE ----
    def destroy(self, request, *args, **kwargs):
        cattle = self.get_object()
        cattle.delete()
        return self.response(False, "Cattle deleted successfully", None, status.HTTP_204_NO_CONTENT)


# Milk collection
class MilkCollectionViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            milk_qs = MilkCollection.objects.all().order_by('-id')

            # Filtering by animal_id
            animal_id = request.query_params.get('animal_id')
            if animal_id:
                milk_qs = milk_qs.filter(animal_id=animal_id)

            # Filtering by session
            session = request.query_params.get('session')
            if session:
                milk_qs = milk_qs.filter(session__iexact=session)

            # Filtering by date range
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            if start_date:
                start_date_parsed = parse_date(start_date)
                if start_date_parsed:
                    milk_qs = milk_qs.filter(collection_date__gte=start_date_parsed)
            if end_date:
                end_date_parsed = parse_date(end_date)
                if end_date_parsed:
                    milk_qs = milk_qs.filter(collection_date__lte=end_date_parsed)

            serializer = MilkCollectionSerializer(milk_qs, many=True)
            return Response({
                "error": False,
                "message": "Filtered Milk Collection Data",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            milk = MilkCollection.objects.get(pk=pk)
            serializer = MilkCollectionSerializer(milk)
            return Response({
                "error": False,
                "message": "Milk Collection Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except MilkCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Milk Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = MilkCollectionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Milk Collection Created",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "error": True,
            "message": "Validation Error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            milk = MilkCollection.objects.get(pk=pk)
            serializer = MilkCollectionSerializer(milk, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Milk Collection Updated",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except MilkCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Milk Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    def partial_update(self, request, pk=None):
        try:
            milk = MilkCollection.objects.get(pk=pk)
            serializer = MilkCollectionSerializer(milk, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Milk Collection Partially Updated",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except MilkCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Milk Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, pk=None):
        try:
            milk = MilkCollection.objects.get(pk=pk)
            milk.delete()
            return Response({
                "error": False,
                "message": "Milk Collection Deleted"
            }, status=status.HTTP_200_OK)
        except MilkCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Milk Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)


# Map geofence
class MapDrawingViewSet(viewsets.ModelViewSet):
    queryset = MapDrawing.objects.all().order_by('-added_on')
    serializer_class = MapDrawingSerializer

    # Role permissions
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    # Custom permissions handler
    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Drawing saved successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "error": False,
            "message": "Drawings fetched successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        return Response({
            "error": False,
            "message": "Drawing retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Drawing updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=True
        )

        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Drawing updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()

        return Response({
            "error": False,
            "message": "Drawing deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# calving records
class CalvingRecordViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            qs = CalvingRecord.objects.all().order_by('-calving_date')

            # Filter by animal_id
            animal_id = request.query_params.get('animal')
            if animal_id:
                qs = qs.filter(animal_id=animal_id)

            # Filter by date range
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")

            if start_date:
                dt = parse_date(start_date)
                if dt:
                    qs = qs.filter(calving_date__gte=dt)

            if end_date:
                dt = parse_date(end_date)
                if dt:
                    qs = qs.filter(calving_date__lte=dt)

            serializer = CalvingRecordSerializer(qs, many=True)
            return Response({
                "error": False,
                "message": "Calving Records Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            record = CalvingRecord.objects.get(pk=pk)
            serializer = CalvingRecordSerializer(record)
            return Response({
                "error": False,
                "message": "Calving Record Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except CalvingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Calving Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = CalvingRecordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Calving Record Created Successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation Error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            record = CalvingRecord.objects.get(pk=pk)
            serializer = CalvingRecordSerializer(record, data=request.data)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Calving Record Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except CalvingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Calving Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    def partial_update(self, request, pk=None):
        try:
            record = CalvingRecord.objects.get(pk=pk)
            serializer = CalvingRecordSerializer(record, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Calving Record Partially Updated",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except CalvingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Calving Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    # ----------------------
    # DELETE
    # ----------------------
    def destroy(self, request, pk=None):
        try:
            record = CalvingRecord.objects.get(pk=pk)
            record.delete()

            return Response({
                "error": False,
                "message": "Calving Record Deleted"
            }, status=status.HTTP_200_OK)

        except CalvingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Calving Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)


# Medication records
class MedicationViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action["default"]
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            qs = Medication.objects.all().order_by("-id")

            # Filter by animal ID
            animal_id = request.query_params.get("animal")
            if animal_id:
                qs = qs.filter(animal_id=animal_id)

            serializer = MedicationSerializer(qs, many=True)
            return Response({
                "error": False,
                "message": "Medications Retrieved",
                "data": serializer.data,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e),
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            medication = Medication.objects.get(pk=pk)
            serializer = MedicationSerializer(medication)
            return Response({
                "error": False,
                "message": "Medication Retrieved",
                "data": serializer.data,
            }, status=status.HTTP_200_OK)

        except Medication.DoesNotExist:
            return Response({
                "error": True,
                "message": "Medication Not Found",
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e),
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = MedicationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Medication Created Successfully",
                "data": serializer.data,
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation Error",
            "details": serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            medication = Medication.objects.get(pk=pk)
            serializer = MedicationSerializer(medication, data=request.data)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Medication Updated Successfully",
                    "data": serializer.data,
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)

        except Medication.DoesNotExist:
            return Response({
                "error": True,
                "message": "Medication Not Found",
            }, status=status.HTTP_404_NOT_FOUND)

    def partial_update(self, request, pk=None):
        try:
            medication = Medication.objects.get(pk=pk)
            serializer = MedicationSerializer(medication, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Medication Partially Updated",
                    "data": serializer.data,
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)

        except Medication.DoesNotExist:
            return Response({
                "error": True,
                "message": "Medication Not Found",
            }, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, pk=None):
        try:
            medication = Medication.objects.get(pk=pk)
            medication.delete()

            return Response({
                "error": False,
                "message": "Medication Deleted",
            }, status=status.HTTP_200_OK)

        except Medication.DoesNotExist:
            return Response({
                "error": True,
                "message": "Medication Not Found",
            }, status=status.HTTP_404_NOT_FOUND)


# Poultry Records
class PoultryRecordViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # ----------------------------------------------------
    # LIST
    # ----------------------------------------------------
    def list(self, request):
        try:
            qs = PoultryBatch.objects.all().order_by("-id")

            # Optional filters
            category = request.query_params.get("category")
            if category:
                qs = qs.filter(category=category)

            breed = request.query_params.get("breed")
            if breed:
                qs = qs.filter(breed__icontains=breed)

            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")

            if start_date:
                dt = parse_date(start_date)
                if dt:
                    qs = qs.filter(created_at__gte=dt)

            if end_date:
                dt = parse_date(end_date)
                if dt:
                    qs = qs.filter(created_at__lte=dt)

            serializer = PoultryRecordSerializer(qs, many=True)

            return Response({
                "error": False,
                "message": "Poultry Records Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # ----------------------------------------------------
    # RETRIEVE
    # ----------------------------------------------------
    def retrieve(self, request, pk=None):
        try:
            record = PoultryBatch.objects.get(pk=pk)
            serializer = PoultryRecordSerializer(record)

            return Response({
                "error": False,
                "message": "Poultry Record Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except PoultryBatch.DoesNotExist:
            return Response({
                "error": True,
                "message": "Poultry Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    # ----------------------------------------------------
    # CREATE
    # ----------------------------------------------------
    def create(self, request):
        serializer = PoultryRecordSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Poultry Record Created Successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation Error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # ----------------------------------------------------
    # UPDATE (PUT)
    # ----------------------------------------------------
    def update(self, request, pk=None):
        try:
            record = PoultryBatch.objects.get(pk=pk)
            serializer = PoultryRecordSerializer(record, data=request.data)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Poultry Record Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except PoultryBatch.DoesNotExist:
            return Response({
                "error": True,
                "message": "Poultry Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    # ----------------------------------------------------
    # PARTIAL UPDATE (PATCH)
    # ----------------------------------------------------
    def partial_update(self, request, pk=None):
        try:
            record = PoultryBatch.objects.get(pk=pk)
            serializer = PoultryRecordSerializer(record, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Poultry Record Partially Updated",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except PoultryBatch.DoesNotExist:
            return Response({
                "error": True,
                "message": "Poultry Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    # ----------------------------------------------------
    # DELETE
    # ----------------------------------------------------
    def destroy(self, request, pk=None):
        try:
            record = PoultryBatch.objects.get(pk=pk)
            record.delete()

            return Response({
                "error": False,
                "message": "Poultry Record Deleted"
            }, status=status.HTTP_200_OK)

        except PoultryBatch.DoesNotExist:
            return Response({
                "error": True,
                "message": "Poultry Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)


# Poultry feeding schedule
class BirdsFeedingScheduleViewSet(viewsets.ModelViewSet):
    queryset = BirdsFeedingSchedule.objects.all().order_by("-start_date")
    serializer_class = BirdsFeedingScheduleSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "error": False,
            "message": "Feeding schedules retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            schedule = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding schedule created successfully",
                "data": self.get_serializer(schedule).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# Poultry feeding record
class BirdsFeedingRecordViewSet(viewsets.ModelViewSet):
    queryset = BirdsFeedingRecord.objects.all().order_by("-date", "-time")
    serializer_class = BirdsFeedingRecordSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # LIST
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "error": False,
            "message": "Feeding records retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    # CREATE
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            record = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding record created successfully",
                "data": self.get_serializer(record).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # RETRIEVE
    def retrieve(self, request, *args, **kwargs):
        try:
            record = self.get_object()
            serializer = self.get_serializer(record)

            return Response({
                "error": False,
                "message": "Feeding record retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except BirdsFeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

    # UPDATE
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)

        try:
            record = self.get_object()
        except BirdsFeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(record, data=request.data, partial=partial)

        if serializer.is_valid():
            record = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding record updated successfully",
                "data": self.get_serializer(record).data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # DESTROY
    def destroy(self, request, *args, **kwargs):
        try:
            record = self.get_object()
        except BirdsFeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        record.delete()

        return Response({
            "error": False,
            "message": "Feeding record deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# Eggs collection records
class EggCollectionViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # ----------------------------------------------------
    # LIST
    # ----------------------------------------------------
    def list(self, request):
        try:
            qs = EggCollection.objects.all().order_by("-collection_date")

            # Optional filters
            batch_id = request.query_params.get("batch_id")
            if batch_id:
                qs = qs.filter(batch_id=batch_id)

            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")

            if start_date:
                dt = parse_date(start_date)
                if dt:
                    qs = qs.filter(collection_date__gte=dt)

            if end_date:
                dt = parse_date(end_date)
                if dt:
                    qs = qs.filter(collection_date__lte=dt)

            serializer = EggCollectionSerializer(qs, many=True)
            return Response({
                "error": False,
                "message": "Egg Collections Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # ----------------------------------------------------
    # RETRIEVE
    # ----------------------------------------------------
    def retrieve(self, request, pk=None):
        try:
            record = EggCollection.objects.get(pk=pk)
            serializer = EggCollectionSerializer(record)
            return Response({
                "error": False,
                "message": "Egg Collection Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except EggCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Egg Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    # ----------------------------------------------------
    # CREATE
    # ----------------------------------------------------
    def create(self, request):
        serializer = EggCollectionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Egg Collection Created Successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation Error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # ----------------------------------------------------
    # UPDATE
    # ----------------------------------------------------
    def update(self, request, pk=None):
        try:
            record = EggCollection.objects.get(pk=pk)
            serializer = EggCollectionSerializer(record, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Egg Collection Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except EggCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Egg Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    # ----------------------------------------------------
    # PARTIAL UPDATE
    # ----------------------------------------------------
    def partial_update(self, request, pk=None):
        try:
            record = EggCollection.objects.get(pk=pk)
            serializer = EggCollectionSerializer(record, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Egg Collection Partially Updated",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except EggCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Egg Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    # ----------------------------------------------------
    # DELETE
    # ----------------------------------------------------
    def destroy(self, request, pk=None):
        try:
            record = EggCollection.objects.get(pk=pk)
            record.delete()
            return Response({
                "error": False,
                "message": "Egg Collection Deleted"
            }, status=status.HTTP_200_OK)

        except EggCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Egg Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)


# Dairy Goats records
class DairyGoatViewSet(viewsets.ModelViewSet):
    queryset = DairyGoat.objects.all().order_by('-id')
    serializer_class = DairyGoatSerializer
    permission_classes = [IsAuthenticated]     # Override per action if needed

    # ---- Filters, search, ordering ----
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['breed', 'category', 'animal_type']
    search_fields = ['animal_name', 'tag_number', 'breed', 'category']
    ordering_fields = ['created_at', 'date_of_birth', 'animal_name']
    # ---- Standard response wrapper ----
    def response(self, error, message, data=None, status_code=status.HTTP_200_OK):
        return Response({
            "error": error,
            "message": message,
            "data": data
        }, status=status_code)

    def create(self, request, *args, **kwargs):
        serializer = DairyGoatSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.response(False, "goat added successfully", serializer.data, status.HTTP_201_CREATED)
        return self.response(True, "Validation Error", serializer.errors, status.HTTP_400_BAD_REQUEST)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = DairyGoatSerializer(queryset, many=True)
        return self.response(False, "goat list fetched", serializer.data)

    def retrieve(self, request, pk=None, *args, **kwargs):
        goat = self.get_object()
        serializer = DairyGoatSerializer(goat)
        return self.response(False, "goat details fetched", serializer.data)

    def update(self, request, *args, **kwargs):
        goat = self.get_object()
        serializer = DairyGoatSerializer(goat, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.response(False, "goat updated successfully", serializer.data)
        return self.response(True, "Validation Error", serializer.errors, status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, **kwargs):
        goat = self.get_object()
        serializer = DairyGoatSerializer(goat, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return self.response(False, "goat updated successfully", serializer.data)
        return self.response(True, "Validation Error", serializer.errors, status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        goat = self.get_object()
        goat.delete()
        return self.response(False, "goat deleted successfully", None, status.HTTP_204_NO_CONTENT)


# Milk collection
class GoatMilkCollectionViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            milk_qs = GoatMilkCollection.objects.all().order_by('-id')

            # Filtering by animal_id
            animal_id = request.query_params.get('animal_id')
            if animal_id:
                milk_qs = milk_qs.filter(animal_id=animal_id)

            # Filtering by session
            session = request.query_params.get('session')
            if session:
                milk_qs = milk_qs.filter(session__iexact=session)

            # Filtering by date range
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            if start_date:
                start_date_parsed = parse_date(start_date)
                if start_date_parsed:
                    milk_qs = milk_qs.filter(collection_date__gte=start_date_parsed)
            if end_date:
                end_date_parsed = parse_date(end_date)
                if end_date_parsed:
                    milk_qs = milk_qs.filter(collection_date__lte=end_date_parsed)

            serializer = GoatMilkCollectionSerializer(milk_qs, many=True)
            return Response({
                "error": False,
                "message": "Filtered Milk Collection Data",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            milk = GoatMilkCollection.objects.get(pk=pk)
            serializer = GoatMilkCollectionSerializer(milk)
            return Response({
                "error": False,
                "message": "Milk Collection Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except GoatMilkCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Milk Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = GoatMilkCollectionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Milk Collection Created",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "error": True,
            "message": "Validation Error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            milk = GoatMilkCollection.objects.get(pk=pk)
            serializer = GoatMilkCollectionSerializer(milk, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Milk Collection Updated",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except GoatMilkCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Milk Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    def partial_update(self, request, pk=None):
        try:
            milk = GoatMilkCollection.objects.get(pk=pk)
            serializer = GoatMilkCollectionSerializer(milk, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Milk Collection Partially Updated",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except GoatMilkCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Milk Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, pk=None):
        try:
            milk = GoatMilkCollection.objects.get(pk=pk)
            milk.delete()
            return Response({
                "error": False,
                "message": "Milk Collection Deleted"
            }, status=status.HTTP_200_OK)
        except GoatMilkCollection.DoesNotExist:
            return Response({
                "error": True,
                "message": "Milk Collection Not Found"
            }, status=status.HTTP_404_NOT_FOUND)


# Kidding records
class KiddingRecordViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            qs = KiddingRecord.objects.all().order_by('-kidding_date')

            # Filter by animal_id
            animal_id = request.query_params.get('animal')
            if animal_id:
                qs = qs.filter(animal_id=animal_id)

            # Filter by date range
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")

            if start_date:
                dt = parse_date(start_date)
                if dt:
                    qs = qs.filter(kidding_date__gte=dt)

            if end_date:
                dt = parse_date(end_date)
                if dt:
                    qs = qs.filter(kidding_date__lte=dt)

            serializer = KiddingRecordSerializer(qs, many=True)
            return Response({
                "error": False,
                "message": "Kidding Records Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            record = KiddingRecord.objects.get(pk=pk)
            serializer = KiddingRecordSerializer(record)
            return Response({
                "error": False,
                "message": "Kidding Record Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except KiddingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Calving Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = KiddingRecordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Kidding Record Created Successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation Error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            record = KiddingRecord.objects.get(pk=pk)
            serializer = KiddingRecordSerializer(record, data=request.data)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Kidding Record Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except KiddingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Calving Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    def partial_update(self, request, pk=None):
        try:
            record = KiddingRecord.objects.get(pk=pk)
            serializer = KiddingRecordSerializer(record, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Kidding Record Partially Updated",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Error",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except KiddingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Kidding Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, pk=None):
        try:
            record = KiddingRecord.objects.get(pk=pk)
            record.delete()

            return Response({
                "error": False,
                "message": "Kidding Record Deleted"
            }, status=status.HTTP_200_OK)

        except KiddingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Kidding Record Not Found"
            }, status=status.HTTP_404_NOT_FOUND)


# Mortality Records
class MortalityRecordViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        records = MortalityRecord.objects.all().order_by("-date")
        serializer = MortalityRecordSerializer(records, many=True)
        return Response({
            "error": False,
            "message": "Mortality records fetched successfully",
            "data": serializer.data
        })

    def create(self, request):
        serializer = MortalityRecordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Mortality record created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation error",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            mortality = MortalityRecord.objects.get(pk=pk)
            mortality.delete()
            return Response({
                "error": False,
                "message": "Mortality record deleted successfully",
                "data": pk
            })
        except MortalityRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Mortality record not found"
            }, status=status.HTTP_404_NOT_FOUND)


# Dairy milk sales
class MilkSaleViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            sales = MilkSale.objects.all().order_by('-id')
            serializer = MilkSaleSerializer(sales, many=True)
            return Response({
                "error": False,
                "message": "Sales Records Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = MilkSaleSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "error": True,
                "message": "Invalid data",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        sale = serializer.save()

        return Response({
            "error": False,
            "message": "Milk sale recorded successfully",
            "data": MilkSaleSerializer(sale).data
        }, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        try:
            sale = MilkSale.objects.get(pk=pk)
            serializer = MilkSaleSerializer(sale)
            return Response({
                "error": False,
                "message": "Sale Record Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except MilkSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            sale = MilkSale.objects.get(pk=pk)
            serializer = MilkSaleSerializer(sale, data=request.data)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Sale updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except MilkSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            sale = MilkSale.objects.get(pk=pk)
            serializer = MilkSaleSerializer(sale, data=request.data, partial=True)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Sale partially updated",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except MilkSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            sale = MilkSale.objects.get(pk=pk)
            sale.delete()
            return Response({
                "error": False,
                "message": "Sale deleted successfully",
                "data": []
            }, status=status.HTTP_200_OK)

        except MilkSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Goat Milk Sales
class GoatMilkSaleViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            sales = GoatMilkSale.objects.all().order_by('-id')
            serializer = GoatMilkSaleSerializer(sales, many=True)
            return Response({
                "error": False,
                "message": "Sales Records Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = GoatMilkSaleSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "error": True,
                "message": "Invalid data",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        sale = serializer.save()

        return Response({
            "error": False,
            "message": "Milk sale recorded successfully",
            "data": GoatMilkSaleSerializer(sale).data
        }, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        try:
            sale = GoatMilkSale.objects.get(pk=pk)
            serializer = GoatMilkSaleSerializer(sale)
            return Response({
                "error": False,
                "message": "Sale Record Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except GoatMilkSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            sale = GoatMilkSale.objects.get(pk=pk)
            serializer = GoatMilkSaleSerializer(sale, data=request.data)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Sale updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except GoatMilkSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            sale = GoatMilkSale.objects.get(pk=pk)
            serializer = GoatMilkSaleSerializer(sale, data=request.data, partial=True)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Sale partially updated",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except GoatMilkSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            sale = GoatMilkSale.objects.get(pk=pk)
            sale.delete()
            return Response({
                "error": False,
                "message": "Sale deleted successfully",
                "data": []
            }, status=status.HTTP_200_OK)

        except GoatMilkSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Egg Sales
class EggSaleViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            sales = EggSale.objects.all().order_by('-id')
            serializer = EggSaleSerializer(sales, many=True)
            return Response({
                "error": False,
                "message": "Sales Records Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = EggSaleSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "error": True,
                "message": "Invalid data",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        sale = serializer.save()

        return Response({
            "error": False,
            "message": "Egg sale recorded successfully",
            "data": EggSaleSerializer(sale).data
        }, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        try:
            sale = EggSale.objects.get(pk=pk)
            serializer = EggSaleSerializer(sale)
            return Response({
                "error": False,
                "message": "Sale Record Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except EggSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            sale = EggSale.objects.get(pk=pk)
            serializer = EggSaleSerializer(sale, data=request.data)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Sale updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except EggSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            sale = EggSale.objects.get(pk=pk)
            serializer = EggSaleSerializer(sale, data=request.data, partial=True)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Sale partially updated",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except EggSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            sale = EggSale.objects.get(pk=pk)
            sale.delete()
            return Response({
                "error": False,
                "message": "Sale deleted successfully",
                "data": []
            }, status=status.HTTP_200_OK)

        except EggSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Customers Records
class CustomerViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            customers = Customers.objects.all().order_by('-id')
            serializer = CustomerSerializer(customers, many=True)

            return Response({
                "error": False,
                "message": "Customers List",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        try:
            serializer = CustomerSerializer(data=request.data)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Customer Created Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "error": True,
                "message": "Validation Failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            customer = get_object_or_404(Customers, pk=pk)
            serializer = CustomerSerializer(customer,   context={"request": request})

            serializer_data = serializer.data

            # Access all milk sales of current customer
            sale_details = Orders.objects.filter(customer=serializer_data["id"]).order_by('-id')
            sale_details_serializer = OrdersSerializer(sale_details, many=True)
            serializer_data["sales"] = sale_details_serializer.data

            return Response({
                "error": False,
                "message": "Customer Retrieved",
                "data": serializer_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "Unable to retrieve customer",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            customer = get_object_or_404(Customers, pk=pk)
            serializer = CustomerSerializer(customer, data=request.data)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Customer Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "Unable to update customer",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            customer = get_object_or_404(Customers, pk=pk)
            serializer = CustomerSerializer(customer, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Customer Partially Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation Failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "Unable to partially update customer",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            customer = get_object_or_404(Customers, pk=pk)
            customer.delete()

            return Response({
                "error": False,
                "message": "Customer Deleted Successfully",
                "data": []
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "Unable to delete customer",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Orders pagination
class OrdersPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


# Orders ViewSet
class OrdersViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            # Pagination setup
            paginator = OrdersPagination()
            orders_qs = Orders.objects.select_related("customer").all().order_by('-id')
            paginated_orders = paginator.paginate_queryset(orders_qs, request)

            serializer = OrdersSerializer(paginated_orders, many=True)

            # Dashboard metrics
            total_revenue = orders_qs.aggregate(total=Sum('total_amount'))['total'] or 0
            avg_transaction = orders_qs.aggregate(avg=Avg('total_amount'))['avg'] or 0
            total_transactions = orders_qs.count()

            # Revenue by category
            category_data = orders_qs.values('category').annotate(total=Sum('total_amount')).order_by('-total')
            category_revenue = [{"name": c['category'].capitalize(), "value": c['total']} for c in category_data]

            # Top category
            if category_revenue:
                top_category = category_revenue[0]['name']
                top_category_amount = category_revenue[0]['value']
            else:
                top_category = None
                top_category_amount = 0

            # Revenue trend per month
            trend_qs = orders_qs.annotate(month=TruncMonth('added_on')).values('month').annotate(
                total=Sum('total_amount')).order_by('month')
            trend = [{"month": t['month'].strftime("%b"), "total": t['total']} for t in trend_qs]

            return paginator.get_paginated_response({
                "error": False,
                "message": "Dashboard Data",
                "data": {
                    "total_revenue": total_revenue,
                    "avg_transaction": avg_transaction,
                    "total_transactions": total_transactions,
                    "top_category": top_category,
                    "top_category_amount": top_category_amount,
                    "category_revenue": category_revenue,
                    "trend": trend,
                    "orders": serializer.data
                }
            })

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            order = Orders.objects.get(pk=pk)
            serializer = OrdersSerializer(order)

            return Response({
                "error": False,
                "message": "Order Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Orders.DoesNotExist:
            return Response({
                "error": True,
                "message": "Order not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # --------------------------
    # CREATE ORDER
    # (Usually created automatically from milk/egg sale)
    # --------------------------
    def create(self, request):
        serializer = OrdersSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "error": True,
                "message": "Invalid order data",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        order = serializer.save()
        return Response({
            "error": False,
            "message": "Order created successfully",
            "data": OrdersSerializer(order).data
        }, status=status.HTTP_201_CREATED)

    def update(self, request, pk=None):
        try:
            order = Orders.objects.get(pk=pk)
            serializer = OrdersSerializer(order, data=request.data)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid update data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Order updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Orders.DoesNotExist:
            return Response({
                "error": True,
                "message": "Order not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            order = Orders.objects.get(pk=pk)
            serializer = OrdersSerializer(order, data=request.data, partial=True)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid update data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Order updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Orders.DoesNotExist:
            return Response({
                "error": True,
                "message": "Order not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            order = Orders.objects.get(pk=pk)
            order.delete()

            return Response({
                "error": False,
                "message": "Order deleted successfully",
                "data": []
            }, status=status.HTTP_200_OK)

        except Orders.DoesNotExist:
            return Response({
                "error": True,
                "message": "Order not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Expense ViewSet
class ExpenseViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            expenses = Expense.objects.all().order_by('-id')
            serializer = ExpenseSerializer(expenses, many=True)
            return Response({
                "error": False,
                "message": "Expenses List",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": True, "message": "An error occurred", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        try:
            serializer = ExpenseSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Expense Created Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({"error": True, "message": "Validation failed", "data": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": True, "message": "An error occurred", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            expense = get_object_or_404(Expense, pk=pk)
            serializer = ExpenseSerializer(expense)
            return Response({"error": False, "message": "Expense Retrieved", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": True, "message": "Unable to retrieve expense", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            expense = get_object_or_404(Expense, pk=pk)
            serializer = ExpenseSerializer(expense, data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response({"error": False, "message": "Expense Updated Successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"error": True, "message": "Validation failed", "data": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": True, "message": "Unable to update expense", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            expense = get_object_or_404(Expense, pk=pk)
            serializer = ExpenseSerializer(expense, data=request.data, partial=True, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response({"error": False, "message": "Expense Partially Updated Successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"error": True, "message": "Validation failed", "data": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": True, "message": "Unable to partially update expense", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            expense = get_object_or_404(Expense, pk=pk)
            expense.delete()
            return Response({"error": False, "message": "Expense Deleted Successfully", "data": []}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": True, "message": "Unable to delete expense", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# Recurring Expense ViewSet
class RecurringExpenseViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            recurring = RecurringExpense.objects.all().order_by('-id')
            serializer = RecurringExpenseSerializer(recurring, many=True)
            return Response({"error": False, "message": "Recurring Expenses List", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": True, "message": "An error occurred", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        try:
            serializer = RecurringExpenseSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save()

                return Response({"error": False, "message": "Recurring Expense Created Successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
            return Response({"error": True, "message": "Validation failed", "data": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": True, "message": "An error occurred", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            recurring = get_object_or_404(RecurringExpense, pk=pk)
            serializer = RecurringExpenseSerializer(recurring)

            # Include generated expenses
            generated = Expense.objects.filter(recurring_expense=recurring.id).order_by('-id')
            generated_serializer = ExpenseSerializer(generated, many=True)
            data = serializer.data
            data["generated_expenses"] = generated_serializer.data

            return Response({"error": False, "message": "Recurring Expense Retrieved", "data": data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": True, "message": "Unable to retrieve recurring expense", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            recurring = get_object_or_404(RecurringExpense, pk=pk)
            serializer = RecurringExpenseSerializer(recurring, data=request.data, context={'request': request})
            if serializer.is_valid():
                updated = serializer.save()

                # Update pending future expenses if any
                Expense.objects.filter(recurring_expense=recurring, status='pending').update(
                    provider_name=updated.provider_name,
                    account_number=updated.account_number
                )

                return Response({"error": False, "message": "Recurring Expense Updated Successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"error": True, "message": "Validation failed", "data": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": True, "message": "Unable to update recurring expense", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            recurring = get_object_or_404(RecurringExpense, pk=pk)
            serializer = RecurringExpenseSerializer(recurring, data=request.data, partial=True, context={'request': request})
            if serializer.is_valid():
                updated = serializer.save()
                Expense.objects.filter(recurring_expense=recurring, status='pending').update(
                    provider_name=updated.provider_name,
                    account_number=updated.account_number
                )
                return Response({"error": False, "message": "Recurring Expense Partially Updated Successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"error": True, "message": "Validation failed", "data": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": True, "message": "Unable to partially update recurring expense", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            recurring = get_object_or_404(RecurringExpense, pk=pk)
            recurring.delete()
            return Response({"error": False, "message": "Recurring Expense Deleted Successfully", "data": []}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": True, "message": "Unable to delete recurring expense", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def generate_due(self, request):
        """Generate all due expenses for the current user"""
        count = RecurringExpense.generate_all_due_expenses(user=request.user)
        return Response({
            'count': count,
            'message': f'Generated {count} due expenses'
        }, status=status.HTTP_200_OK)


# Dashboard summary
class DashboardViewSet(viewsets.ViewSet):

    permission_classes_by_action = {
        'list': [IsAuthenticated],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(
            self.action, self.permission_classes_by_action['default']
        )]

    def list(self, request):
        today = now().date()

        milk_total = MilkCollection.objects.filter(
            added_on__date=today
        ).aggregate(total=Sum('quantity'))['total'] or 0

        goatmilk_total = GoatMilkCollection.objects.filter(
            added_on__date=today
        ).aggregate(total=Sum('quantity'))['total'] or 0

        egg_total = EggCollection.objects.filter(
            added_on__date=today
        ).aggregate(total=Sum('total_eggs'))['total'] or 0

        # If you don’t have vegetable or fish models yet:
        vegetables_total = 0
        fish_total = 0
        milk = milk_total + goatmilk_total

        total_sales = Orders.objects.aggregate(total=Sum("total_amount"))["total"] or 0
        bills = Expense.objects.aggregate(total=Sum("amount"))["total"] or 0
        expenses = BillPayment.objects.aggregate(total=Sum("amount"))["total"] or 0
        procurement = Procurement.objects.aggregate(total=Sum("total_cost"))["total"] or 0

        total_expense = bills + expenses
        total_profit = total_sales - (bills + expenses + procurement)


        dict_response = {
            "error": False,
            "message": "Home page data",
            "milk": milk,
            "eggs": egg_total,
            "vegetables": vegetables_total,
            "fish": fish_total,
            "procurement": procurement,
            "total_sales": total_sales,
            "total_expense": total_expense,
            "total_profit": total_profit,
        }

        return Response(dict_response)


# Tasks viewSets
class TaskViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAuthenticated],
        'list': [IsAuthenticated],
        'retrieve': [IsAuthenticated],
        'update': [IsAuthenticated],
        'partial_update': [IsAuthenticated],
        'destroy': [IsAuthenticated],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(
            self.action, self.permission_classes_by_action['default']
        )]

    def list(self, request):
        tasks = Tasks.objects.all().order_by("-added_on")
        serializer = TaskSerializer(tasks, many=True)
        return Response({
            "error": False,
            "message": "Tasks retrieved successfully",
            "data": serializer.data
        })

    def retrieve(self, request, pk=None):
        try:
            task = Tasks.objects.get(pk=pk)
            serializer = TaskSerializer(task)
            return Response({
                "error": False,
                "message": "Task retrieved successfully",
                "data": serializer.data
            })
        except Tasks.DoesNotExist:
            return Response({
                "error": True,
                "message": "Task not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

    def create(self, request):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Task created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "error": True,
            "message": "Failed to create task",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            task = Tasks.objects.get(pk=pk)
        except Tasks.DoesNotExist:
            return Response({
                "error": True,
                "message": "Task not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = TaskSerializer(task, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Task updated successfully",
                "data": serializer.data
            })
        return Response({
            "error": True,
            "message": "Failed to update task",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            task = Tasks.objects.get(pk=pk)
        except Tasks.DoesNotExist:
            return Response({
                "error": True,
                "message": "Task not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = TaskSerializer(task, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Task partially updated successfully",
                "data": serializer.data
            })
        return Response({
            "error": True,
            "message": "Failed to update task",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            task = Tasks.objects.get(pk=pk)
            task.delete()
            return Response({
                "error": False,
                "message": "Task deleted successfully",
                "data": None
            })
        except Tasks.DoesNotExist:
            return Response({
                "error": True,
                "message": "Task not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)


# Bill payment viewSet
class BillPaymentViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        try:
            payments = BillPayment.objects.all().order_by('-payment_date')
            serializer = BillPaymentSerializer(payments, many=True)
            return Response({
                "error": False,
                "message": "Bill Payments List",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        try:
            serializer = BillPaymentSerializer(data=request.data)
            if serializer.is_valid():
                payment = serializer.save()
                return Response({
                    "error": False,
                    "message": "Bill Payment Created Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({
                "error": True,
                "message": "Validation failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            payment = get_object_or_404(BillPayment, pk=pk)
            serializer = BillPaymentSerializer(payment)
            return Response({
                "error": False,
                "message": "Bill Payment Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Unable to retrieve bill payment",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            payment = get_object_or_404(BillPayment, pk=pk)
            serializer = BillPaymentSerializer(payment, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Bill Payment Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Unable to update bill payment",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            payment = get_object_or_404(BillPayment, pk=pk)
            serializer = BillPaymentSerializer(payment, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Bill Payment Partially Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Unable to partially update bill payment",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            payment = get_object_or_404(BillPayment, pk=pk)
            payment.delete()
            return Response({
                "error": False,
                "message": "Bill Payment Deleted Successfully",
                "data": []
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Unable to delete bill payment",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Procurement viewSet
class ProcurementViewSet(viewsets.ModelViewSet):
    queryset = Procurement.objects.all().order_by("-purchase_date")
    serializer_class = ProcurementSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "error": False,
            "message": "Procurement records retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            procurement = serializer.save()

            return Response({
                "error": False,
                "message": "Procurement record created successfully",
                "data": self.get_serializer(procurement).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, *args, **kwargs):
        try:
            procurement = self.get_object()
            serializer = self.get_serializer(procurement)

            return Response({
                "error": False,
                "message": "Procurement record retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Procurement.DoesNotExist:
            return Response({
                "error": True,
                "message": "Procurement record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)

        try:
            procurement = self.get_object()
        except Procurement.DoesNotExist:
            return Response({
                "error": True,
                "message": "Procurement record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(procurement, data=request.data, partial=partial)

        if serializer.is_valid():
            procurement = serializer.save()

            return Response({
                "error": False,
                "message": "Procurement record updated successfully",
                "data": self.get_serializer(procurement).data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            procurement = self.get_object()
        except Procurement.DoesNotExist:
            return Response({
                "error": True,
                "message": "Procurement record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        procurement.delete()

        return Response({
            "error": False,
            "message": "Procurement record deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# Inventory pagination
class InventoryPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


# Inventory viewSet
class InventoryViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            paginator = InventoryPagination()

            inventory_qs = Inventory.objects.all().order_by('-id')
            paginated = paginator.paginate_queryset(inventory_qs, request)
            serializer = InventorySerializer(paginated, many=True)

            # Dashboard Metrics
            total_stock_value = inventory_qs.aggregate(
                value=Sum(models.F("current_stock") * models.F("unit_cost"))
            )['value'] or 0

            avg_unit_cost = inventory_qs.aggregate(
                avg=Avg('unit_cost')
            )['avg'] or 0

            total_items = inventory_qs.count()

            low_stock = inventory_qs.filter(
                current_stock__lte=models.F("min_threshold")
            ).count()

            # Total value by category
            category_summary = inventory_qs.values('category').annotate(
                total_value=Sum(models.F("current_stock") * models.F("unit_cost"))
            ).order_by('-total_value')

            category_data = [
                {"name": c['category'].capitalize(), "value": c['total_value']}
                for c in category_summary
            ]

            # Monthly valuation trend
            trend_qs = inventory_qs.annotate(
                month=TruncMonth('updated_on')
            ).values('month').annotate(
                total=Sum(models.F("current_stock") * models.F("unit_cost"))
            ).order_by('month')

            trend = [
                {"month": t["month"].strftime("%b"), "total": t['total']}
                for t in trend_qs
            ]

            return paginator.get_paginated_response({
                "error": False,
                "message": "Inventory Dashboard Data",
                "data": {
                    "total_stock_value": total_stock_value,
                    "avg_unit_cost": avg_unit_cost,
                    "total_items": total_items,
                    "low_stock": low_stock,
                    "category_value": category_data,
                    "trend": trend,
                    "items": serializer.data
                }
            })

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = InventorySerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "error": True,
                "message": "Invalid inventory data",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        item = serializer.save()
        return Response({
            "error": False,
            "message": "Inventory item created successfully",
            "data": InventorySerializer(item).data
        }, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        try:
            item = Inventory.objects.get(pk=pk)
            serializer = InventorySerializer(item)

            return Response({
                "error": False,
                "message": "Inventory item retrieved",
                "data": serializer.data
            })

        except Inventory.DoesNotExist:
            return Response({
                "error": True,
                "message": "Item not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            item = Inventory.objects.get(pk=pk)
            serializer = InventorySerializer(item, data=request.data)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid update data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Inventory item updated successfully",
                "data": serializer.data
            })

        except Inventory.DoesNotExist:
            return Response({
                "error": True,
                "message": "Item not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            item = Inventory.objects.get(pk=pk)
            serializer = InventorySerializer(item, data=request.data, partial=True)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid update data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Inventory item updated successfully",
                "data": serializer.data
            })

        except Inventory.DoesNotExist:
            return Response({
                "error": True,
                "message": "Item not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            item = Inventory.objects.get(pk=pk)
            item.delete()

            return Response({
                "error": False,
                "message": "Inventory item deleted",
                "data": []
            })

        except Inventory.DoesNotExist:
            return Response({
                "error": True,
                "message": "Item not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Rabbit viewSet
class RabbitViewSet(viewsets.ModelViewSet):
    queryset = Rabbit.objects.all().order_by('-id')
    serializer_class = RabbitSerializer
    permission_classes = [IsAuthenticated]     # Override per action if needed

    # ---- Filters, search, ordering ----
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['breed', 'category', 'animal_type']
    search_fields = ['animal_name', 'breed', 'category']
    ordering_fields = ['added_on', 'date_of_birth', 'animal_name']
    # ---- Standard response wrapper ----
    def response(self, error, message, data=None, status_code=status.HTTP_200_OK):
        return Response({
            "error": error,
            "message": message,
            "data": data
        }, status=status_code)

    def create(self, request, *args, **kwargs):
        serializer = RabbitSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.response(False, "Rabbit added successfully", serializer.data, status.HTTP_201_CREATED)
        return self.response(True, "Validation Error", serializer.errors, status.HTTP_400_BAD_REQUEST)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = RabbitSerializer(queryset, many=True)
        return self.response(False, "rabbit list fetched", serializer.data)

    def retrieve(self, request, pk=None, *args, **kwargs):
        rabbit = self.get_object()
        serializer = RabbitSerializer(rabbit)
        return self.response(False, "rabbit details fetched", serializer.data)

    def update(self, request, *args, **kwargs):
        rabbit = self.get_object()
        serializer = RabbitSerializer(rabbit, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.response(False, "rabbit updated successfully", serializer.data)
        return self.response(True, "Validation Error", serializer.errors, status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, **kwargs):
        rabbit = self.get_object()
        serializer = RabbitSerializer(rabbit, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return self.response(False, "rabbit updated successfully", serializer.data)
        return self.response(True, "Validation Error", serializer.errors, status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        rabbit = self.get_object()
        rabbit.delete()
        return self.response(False, "rabbit deleted successfully", None, status.HTTP_204_NO_CONTENT)


# Pond viewSet
class PondViewSet(viewsets.ModelViewSet):
    queryset = Pond.objects.all().order_by("-id")
    serializer_class = PondSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # LIST
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({
            "error": False,
            "message": "Ponds retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    # CREATE
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            pond = serializer.save()
            return Response({
                "error": False,
                "message": "Pond created successfully",
                "data": self.get_serializer(pond).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # RETRIEVE
    def retrieve(self, request, *args, **kwargs):
        pond = self.get_object()
        return Response({
            "error": False,
            "message": "Pond retrieved successfully",
            "data": self.get_serializer(pond).data
        }, status=status.HTTP_200_OK)

    # UPDATE
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        pond = self.get_object()

        serializer = self.get_serializer(pond, data=request.data, partial=partial)
        if serializer.is_valid():
            pond = serializer.save()
            return Response({
                "error": False,
                "message": "Pond updated successfully",
                "data": self.get_serializer(pond).data
            })

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # DESTROY
    def destroy(self, request, *args, **kwargs):
        pond = self.get_object()
        pond.delete()

        return Response({
            "error": False,
            "message": "Pond deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# Catfish batch viewSet
class CatfishBatchViewSet(viewsets.ModelViewSet):
    queryset = CatfishBatch.objects.select_related("pond").all().order_by("-id")
    serializer_class = CatfishSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # LIST
    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return Response({
            "error": False,
            "message": "Catfish batches retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    # CREATE
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            batch = serializer.save()
            return Response({
                "error": False,
                "message": "Catfish batch created successfully",
                "data": self.get_serializer(batch).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # RETRIEVE
    def retrieve(self, request, *args, **kwargs):
        batch = self.get_object()
        return Response({
            "error": False,
            "message": "Catfish batch retrieved successfully",
            "data": self.get_serializer(batch).data
        }, status=status.HTTP_200_OK)

    # UPDATE
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        batch = self.get_object()

        serializer = self.get_serializer(batch, data=request.data, partial=partial)
        if serializer.is_valid():
            batch = serializer.save()
            return Response({
                "error": False,
                "message": "Catfish batch updated successfully",
                "data": self.get_serializer(batch).data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # DESTROY
    def destroy(self, request, *args, **kwargs):
        batch = self.get_object()
        batch.delete()

        return Response({
            "error": False,
            "message": "Catfish batch deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# Catfish sales viewset
class CatfishSaleViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            sales = CatfishSale.objects.all().order_by('-id')
            serializer = CatfishSaleSerializer(sales, many=True)
            return Response({
                "error": False,
                "message": "Sales Records Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = CatfishSaleSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "error": True,
                "message": "Invalid data",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        sale = serializer.save()

        return Response({
            "error": False,
            "message": "Egg sale recorded successfully",
            "data": CatfishSaleSerializer(sale).data
        }, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        try:
            sale = CatfishSale.objects.get(pk=pk)
            serializer = CatfishSaleSerializer(sale)
            return Response({
                "error": False,
                "message": "Sale Record Retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except CatfishSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            sale = CatfishSale.objects.get(pk=pk)
            serializer = CatfishSaleSerializer(sale, data=request.data)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Sale updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except CatfishSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            sale = CatfishSale.objects.get(pk=pk)
            serializer = CatfishSaleSerializer(sale, data=request.data, partial=True)

            if not serializer.is_valid():
                return Response({
                    "error": True,
                    "message": "Invalid data",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()

            return Response({
                "error": False,
                "message": "Sale partially updated",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except CatfishSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            sale = CatfishSale.objects.get(pk=pk)
            sale.delete()
            return Response({
                "error": False,
                "message": "Sale deleted successfully",
                "data": []
            }, status=status.HTTP_200_OK)

        except CatfishSale.DoesNotExist:
            return Response({
                "error": True,
                "message": "Sale not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Catfish feeding schedule
class FeedingScheduleViewSet(viewsets.ModelViewSet):
    queryset = FeedingSchedule.objects.all().order_by("-start_date")
    serializer_class = FeedingScheduleSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "error": False,
            "message": "Feeding schedules retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            schedule = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding schedule created successfully",
                "data": self.get_serializer(schedule).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# Catfish feeding record
class FeedingRecordViewSet(viewsets.ModelViewSet):
    queryset = FeedingRecord.objects.all().order_by("-date", "-time")
    serializer_class = FeedingRecordSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # LIST
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "error": False,
            "message": "Feeding records retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    # CREATE
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            record = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding record created successfully",
                "data": self.get_serializer(record).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # RETRIEVE
    def retrieve(self, request, *args, **kwargs):
        try:
            record = self.get_object()
            serializer = self.get_serializer(record)

            return Response({
                "error": False,
                "message": "Feeding record retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except FeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

    # UPDATE
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)

        try:
            record = self.get_object()
        except FeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(record, data=request.data, partial=partial)

        if serializer.is_valid():
            record = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding record updated successfully",
                "data": self.get_serializer(record).data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # DESTROY
    def destroy(self, request, *args, **kwargs):
        try:
            record = self.get_object()
        except FeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        record.delete()

        return Response({
            "error": False,
            "message": "Feeding record deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# Dairy Cattle Feeding Schedule ViewSet
class DairyCattleFeedingScheduleViewSet(viewsets.ModelViewSet):
    queryset = DairyCattleFeedingSchedule.objects.all().order_by("-id")
    serializer_class = DairyCattleFeedingScheduleSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # REMOVED THE FILTER HERE
    def get_queryset(self):
        return self.queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "error": False,
            "message": "Dairy cattle feeding schedules retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            schedule = serializer.save()
            return Response({
                "error": False,
                "message": "Feeding schedule created successfully",
                "data": self.get_serializer(schedule).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, *args, **kwargs):
        try:
            schedule = self.get_object()
            serializer = self.get_serializer(schedule)
            return Response({
                "error": False,
                "message": "Feeding schedule retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except DairyCattleFeedingSchedule.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding schedule not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        try:
            schedule = self.get_object()
        except DairyCattleFeedingSchedule.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding schedule not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(schedule, data=request.data, partial=partial)
        if serializer.is_valid():
            schedule = serializer.save()
            return Response({
                "error": False,
                "message": "Feeding schedule updated successfully",
                "data": self.get_serializer(schedule).data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            schedule = self.get_object()
        except DairyCattleFeedingSchedule.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding schedule not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        schedule.delete()
        return Response({
            "error": False,
            "message": "Feeding schedule deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# Dairy Cattle Feeding Record ViewSet
class DairyCattleFeedingRecordViewSet(viewsets.ModelViewSet):
    queryset = DairyCattleFeedingRecord.objects.all().order_by("-id")
    serializer_class = DairyCattleFeedingRecordSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def get_queryset(self):
        return self.queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "error": False,
            "message": "Dairy cattle feeding records retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            record = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding record created successfully",
                "data": self.get_serializer(record).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, *args, **kwargs):
        try:
            record = self.get_object()
        except DairyCattleFeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(record)

        return Response({
            "error": False,
            "message": "Feeding record retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)

        try:
            record = self.get_object()
        except DairyCattleFeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(record, data=request.data, partial=partial)

        if serializer.is_valid():
            record = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding record updated successfully",
                "data": self.get_serializer(record).data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            record = self.get_object()
        except DairyCattleFeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        record.delete()

        return Response({
            "error": False,
            "message": "Feeding record deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# Dairy Goat Feeding Schedule ViewSet
class DairyGoatFeedingScheduleViewSet(viewsets.ModelViewSet):
    queryset = DairyGoatFeedingSchedule.objects.all().order_by("-id")
    serializer_class = DairyGoatFeedingScheduleSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def get_queryset(self):
        return self.queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "error": False,
            "message": "Dairy goat feeding schedules retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            schedule = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding schedule created successfully",
                "data": self.get_serializer(schedule).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, *args, **kwargs):
        try:
            schedule = self.get_object()
            serializer = self.get_serializer(schedule)

            return Response({
                "error": False,
                "message": "Feeding schedule retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except DairyGoatFeedingSchedule.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding schedule not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)

        try:
            schedule = self.get_object()
        except DairyGoatFeedingSchedule.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding schedule not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(schedule, data=request.data, partial=partial)

        if serializer.is_valid():
            schedule = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding schedule updated successfully",
                "data": self.get_serializer(schedule).data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            schedule = self.get_object()
        except DairyGoatFeedingSchedule.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding schedule not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        schedule.delete()

        return Response({
            "error": False,
            "message": "Feeding schedule deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# Dairy Goat Feeding Record ViewSet
class DairyGoatFeedingRecordViewSet(viewsets.ModelViewSet):
    queryset = DairyGoatFeedingRecord.objects.all().order_by("-id")
    serializer_class = DairyGoatFeedingRecordSerializer

    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def get_queryset(self):
        schedule_id = self.request.query_params.get("schedule_id")
        goat_id = self.request.query_params.get("goat_id")

        queryset = self.queryset

        if schedule_id:
            queryset = queryset.filter(schedule_id=schedule_id)

        if goat_id:
            queryset = queryset.filter(schedule__goat_id=goat_id)

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "error": False,
            "message": "Dairy cattle feeding records retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            record = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding record created successfully",
                "data": self.get_serializer(record).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, *args, **kwargs):
        try:
            record = self.get_object()
        except DairyGoatFeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(record)

        return Response({
            "error": False,
            "message": "Feeding record retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)

        try:
            record = self.get_object()
        except DairyGoatFeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(record, data=request.data, partial=partial)

        if serializer.is_valid():
            record = serializer.save()

            return Response({
                "error": False,
                "message": "Feeding record updated successfully",
                "data": self.get_serializer(record).data
            }, status=status.HTTP_200_OK)

        return Response({
            "error": True,
            "message": "Validation failed",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            record = self.get_object()
        except DairyGoatFeedingRecord.DoesNotExist:
            return Response({
                "error": True,
                "message": "Feeding record not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        record.delete()

        return Response({
            "error": False,
            "message": "Feeding record deleted successfully",
            "data": None
        }, status=status.HTTP_200_OK)


# Book and pay
class BookingPaymentViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        "create": [AllowAny],
        "list": [IsAuthenticated],
        "update": [IsAuthenticated],
        "retrieve": [AllowAny],
        "destroy": [IsAuthenticated],
        "default": [AllowAny],
    }

    def get_permissions(self):
        return [
            permission() for permission in
            self.permission_classes_by_action.get(
                self.action, self.permission_classes_by_action["default"]
            )
        ]

    def create(self, request):
        try:
            name = request.data.get("name")
            email = request.data.get("email")
            phone = request.data.get("phone")
            visit_date = request.data.get("visit_date")
            time_slot = request.data.get("time_slot")
            number_of_visitors = int(request.data.get("number_of_visitors", 1))
            total_amount = float(request.data.get("total_amount"))

            # Validate mandatory fields
            missing = [f for f in ["name", "email", "phone", "visit_date", "time_slot", "total_amount"]
                       if not request.data.get(f)]
            if missing:
                return Response(
                    {"error": True, "message": f"Missing required fields: {', '.join(missing)}"},
                    status=400
                )

            # Create booking with pending status
            booking = FarmVisitBooking.objects.create(
                name=name,
                email=email,
                phone=phone,
                visit_date=visit_date,
                time_slot=time_slot,
                number_of_visitors=number_of_visitors,
                total_amount=total_amount,
                added_on=timezone.now(),
            )

            # Initiate STK push
            mpesa = MpesaService()
            stk_result = mpesa.initiate_stk_push(
                phone=phone,
                amount=total_amount,
                reference=f"BOOK-{booking.id}",
                description="Farm Visit Booking Payment"
            )

            if stk_result.get("ResponseCode") == "0":
                # Create payment
                payment = MpesaPayment.objects.create(
                    checkout_request_id=stk_result["CheckoutRequestID"],
                    phone_number=phone,
                    amount=total_amount,
                    status="pending",
                    result_code=stk_result.get("ResponseCode"),
                    result_description=stk_result.get("ResponseDescription"),
                )

                # Assign payment to booking
                booking.payment = payment
                booking.save()

                serializer = BookingsSerializer(booking)
                return Response(
                    {
                        "error": False,
                        "message": f"STK Push sent to {phone}. Complete the payment to confirm your booking.",
                        "data": serializer.data,
                    },
                    status=status.HTTP_201_CREATED,
                )

            # STK initiation failed
            return Response(
                {"error": True, "message": "Failed to initiate M-PESA STK Push", "data": stk_result},
                status=400,
            )

        except Exception as e:
            return Response(
                {"error": True, "message": "Booking creation failed", "details": str(e)},
                status=500
            )

    def list(self, request):
        bookings = FarmVisitBooking.objects.all().order_by("-id")
        serializer = BookingsSerializer(bookings, many=True)
        return Response(
            {"error": False, "message": "All Bookings", "data": serializer.data},
            status=200
        )

    def retrieve(self, request, pk):
        booking = get_object_or_404(FarmVisitBooking, pk=pk)
        serializer = BookingsSerializer(booking)
        return Response(
            {"error": False, "message": "Booking Details", "data": serializer.data},
            status=200
        )

    # ---------------------------------------------------------
    # UPDATE (PUT/PATCH)
    # ---------------------------------------------------------

    def update(self, request, pk=None):
        return self._update_booking(request, pk, partial=False)

    def partial_update(self, request, pk=None):
        return self._update_booking(request, pk, partial=True)

    def _update_booking(self, request, pk, partial):
        try:
            booking = get_object_or_404(FarmVisitBooking, pk=pk)

            # Prevent alteration of payment objects
            protected_fields = ["payment", "checkout_request_id", "result_code"]
            for f in protected_fields:
                if f in request.data:
                    return Response(
                        {"error": True, "message": f"Field '{f}' cannot be modified."},
                        status=400
                    )

            serializer = BookingsSerializer(booking, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {"error": False, "message": "Booking updated successfully", "data": serializer.data},
                status=200
            )

        except Exception as e:
            return Response(
                {"error": True, "message": "Failed to update booking", "details": str(e)},
                status=500
            )

        # ---------------------------------------------------------
        # DELETE
        # ---------------------------------------------------------

    def destroy(self, request, pk):
        try:
            booking = get_object_or_404(FarmVisitBooking, pk=pk)
            booking.delete()
            return Response(
                {"error": False, "message": "Booking deleted successfully"},
                status=200
            )
        except Exception as e:
            return Response(
                {"error": True, "message": "Failed to delete booking", "details": str(e)},
                status=500
            )


# mpesa farm bookings
class MpesaViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    @action(detail=False, methods=["post"])
    def pay(self, request):
        phone = request.data.get("phone_number")
        amount = request.data.get("amount")
        booking_id = request.data.get("booking_id")  # use booking instead of donation
        description = request.data.get("description", "Farm visit payment")

        if not phone or not amount or not booking_id:
            return Response(
                {
                    "error": True,
                    "message": "phone_number, amount, and booking_id are required.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate booking exists
        booking = FarmVisitBooking.objects.filter(id=booking_id).first()
        if not booking:
            return Response(
                {"error": True, "message": "Booking not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        mpesa = MpesaService()

        try:
            response = mpesa.initiate_stk_push(
                phone_number=phone,
                amount=amount,
                reference=f"BOOKING-{booking_id}",
                description=description,
            )

            if response.get("ResponseCode") == "0":
                # Create pending payment record
                payment = MpesaPayment.objects.create(
                    checkout_request_id=response.get("CheckoutRequestID"),
                    phone_number=phone,
                    amount=amount,
                    status="pending",
                    result_code=response.get("ResponseCode"),
                    result_description=response.get("ResponseDescription"),
                )

                # Link booking → payment
                booking.payment = payment
                booking.save()

                serializer = BookingsSerializer(booking)

                return Response(
                    {
                        "error": False,
                        "message": "STK Push sent. Complete payment on your phone.",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )

            return Response(
                {
                    "error": True,
                    "message": response.get("errorMessage", "Failed to initiate STK push."),
                    "data": response,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            return Response(
                {"error": True, "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["post"])
    def callback(self, request):
        callback_data = request.data.get("Body", {}).get("stkCallback")

        if not callback_data:
            return Response(
                {"error": True, "message": "Invalid callback payload"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        checkout_id = callback_data.get("CheckoutRequestID")
        result_code = int(callback_data.get("ResultCode", -1))
        result_desc = callback_data.get("ResultDesc")

        payment = MpesaPayment.objects.filter(checkout_request_id=checkout_id).first()
        if not payment:
            return Response(
                {"error": True, "message": "Payment record not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # SUCCESS CASE
        if result_code == 0:
            metadata = {}
            for item in callback_data.get("CallbackMetadata", {}).get("Item", []):
                metadata[item.get("Name")] = item.get("Value")

            phone = metadata.get("PhoneNumber", payment.phone_number)
            amount = metadata.get("Amount", payment.amount)
            receipt = metadata.get("MpesaReceiptNumber")
            trx_date_str = metadata.get("TransactionDate")

            trx_date = timezone.now()
            if trx_date_str:
                try:
                    trx_date = datetime.strptime(str(trx_date_str), "%Y%m%d%H%M%S")
                except:
                    pass

            payment.phone_number = phone
            payment.amount = amount
            payment.receipt = receipt
            payment.transaction_date = trx_date
            payment.status = "success"
            payment.result_code = result_code
            payment.result_description = result_desc
            payment.save()

            booking = FarmVisitBooking.objects.filter(payment=payment).first()
            serializer = BookingsSerializer(booking)

            return Response(
                {
                    "error": False,
                    "message": "Payment successful and booking updated.",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

        # FAILURE CASE
        payment.status = "failed"
        payment.result_code = result_code
        payment.result_description = result_desc
        payment.save()

        return Response(
            {"error": True, "message": f"Payment failed: {result_desc}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    @action(detail=False, methods=["get"])
    def check_status(self, request):
        checkout_id = request.query_params.get("checkout_request_id")

        if not checkout_id:
            return Response(
                {"error": True, "message": "checkout_request_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        payment = MpesaPayment.objects.filter(checkout_request_id=checkout_id).first()
        if not payment:
            return Response(
                {"error": True, "message": "Payment record not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        booking = FarmVisitBooking.objects.filter(payment=payment).first()
        if not booking:
            return Response(
                {"error": True, "message": "Booking not found for this payment"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = BookingsSerializer(booking)

        return Response(
            {
                "error": False,
                "message": "Payment status retrieved",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


# Plots viewset
class PlotsViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # -------------------------------------
    # LIST
    # -------------------------------------
    def list(self, request):
        try:
            plots = Plot.objects.all().order_by('-id')
            serializer = PlotSerializer(plots, many=True)
            return Response({
                "error": False,
                "message": "Plots List",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # CREATE
    # -------------------------------------
    def create(self, request):
        try:
            serializer = PlotSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Plot Created Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "error": True,
                "message": "Validation failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # RETRIEVE
    # -------------------------------------
    def retrieve(self, request, pk=None):
        try:
            plots = Plot.objects.get(id=pk)
            serializer = PlotSerializer(plots)
            return Response({
                "error": False,
                "message": "Plant Details",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Plot.DoesNotExist:
            return Response({
                "error": True,
                "message": "Plant not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # UPDATE (PUT)
    # -------------------------------------
    def update(self, request, pk=None):
        try:
            plots = Plot.objects.get(id=pk)
            serializer = PlotSerializer(plots, data=request.data, context={'request': request})

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Plant Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Plot.DoesNotExist:
            return Response({
                "error": True,
                "message": "Plant not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # PARTIAL UPDATE (PATCH)
    # -------------------------------------
    def partial_update(self, request, pk=None):
        try:
            plots = Plot.objects.get(id=pk)
            serializer = PlotSerializer(plots, data=request.data, partial=True, context={'request': request})

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Plant Partially Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Plot.DoesNotExist:
            return Response({
                "error": True,
                "message": "Plant not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # DELETE
    # -------------------------------------
    def destroy(self, request, pk=None):
        try:
            plots = Plot.objects.get(id=pk)
            plots.delete()

            return Response({
                "error": False,
                "message": "Plant Deleted Successfully",
                "data": None
            }, status=status.HTTP_200_OK)

        except Plot.DoesNotExist:
            return Response({
                "error": True,
                "message": "Plant not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Plants viewset
class PlantsViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'retrieve': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'partial_update': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action['default']
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # -------------------------------------
    # LIST
    # -------------------------------------
    def list(self, request):
        try:
            plants = FarmPlants.objects.all().order_by('-id')
            serializer = FarmPlantsSerializer(plants, many=True)
            return Response({
                "error": False,
                "message": "Farm Plants List",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # CREATE
    # -------------------------------------
    def create(self, request):
        try:
            serializer = FarmPlantsSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Farm Plant Created Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "error": True,
                "message": "Validation failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # RETRIEVE
    # -------------------------------------
    def retrieve(self, request, pk=None):
        try:
            plant = FarmPlants.objects.get(id=pk)
            serializer = FarmPlantsSerializer(plant)
            return Response({
                "error": False,
                "message": "Plant Details",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except FarmPlants.DoesNotExist:
            return Response({
                "error": True,
                "message": "Plant not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # UPDATE (PUT)
    # -------------------------------------
    def update(self, request, pk=None):
        try:
            plant = FarmPlants.objects.get(id=pk)
            serializer = FarmPlantsSerializer(plant, data=request.data, context={'request': request})

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Plant Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except FarmPlants.DoesNotExist:
            return Response({
                "error": True,
                "message": "Plant not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # PARTIAL UPDATE (PATCH)
    # -------------------------------------
    def partial_update(self, request, pk=None):
        try:
            plant = FarmPlants.objects.get(id=pk)
            serializer = FarmPlantsSerializer(plant, data=request.data, partial=True, context={'request': request})

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Plant Partially Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation failed",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except FarmPlants.DoesNotExist:
            return Response({
                "error": True,
                "message": "Plant not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------------------
    # DELETE
    # -------------------------------------
    def destroy(self, request, pk=None):
        try:
            plant = FarmPlants.objects.get(id=pk)
            plant.delete()

            return Response({
                "error": False,
                "message": "Plant Deleted Successfully",
                "data": None
            }, status=status.HTTP_200_OK)

        except FarmPlants.DoesNotExist:
            return Response({
                "error": True,
                "message": "Plant not found",
                "data": None
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Crop planting viewSet
class CropPlantingViewSet(viewsets.ModelViewSet):
    queryset = CropPlanting.objects.select_related("plot", "plant").order_by("-id")
    serializer_class = CropPlantingSerializer

    permission_classes_by_action = {
        "create": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "list": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "retrieve": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "update": [IsAdminRole, IsFarmManagerRole],
        "partial_update": [IsAdminRole, IsFarmManagerRole],
        "destroy": [IsAdminRole, IsFarmManagerRole],
        "default": [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action["default"]
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # -------------------------
    # LIST (supports ?plant=ID)
    # -------------------------
    def list(self, request):
        try:
            queryset = self.get_queryset()

            plant_id = request.query_params.get("plant")
            if plant_id:
                queryset = queryset.filter(plant_id=plant_id)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "error": False,
                "message": "Crop plantings list",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # CREATE
    # -------------------------
    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Crop planting created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # RETRIEVE
    # -------------------------
    def retrieve(self, request, pk=None):
        planting = get_object_or_404(CropPlanting, pk=pk)
        serializer = self.get_serializer(planting)
        return Response({
            "error": False,
            "message": "Crop planting retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    # -------------------------
    # UPDATE / PARTIAL UPDATE
    # -------------------------
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        pk = kwargs.get("pk")

        try:
            planting = get_object_or_404(CropPlanting, pk=pk)
            serializer = self.get_serializer(
                planting,
                data=request.data,
                partial=partial
            )

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Crop planting updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # DELETE
    # -------------------------
    def destroy(self, request, pk=None):
        try:
            planting = get_object_or_404(CropPlanting, pk=pk)
            planting.delete()
            return Response({
                "error": False,
                "message": "Crop planting deleted successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Crop harvest viewSet
class CropHarvestViewSet(viewsets.ModelViewSet):
    queryset = CropHarvest.objects.select_related("planting").order_by("-id")
    serializer_class = CropHarvestSerializer

    permission_classes_by_action = {
        "create": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "list": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "retrieve": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "update": [IsAdminRole, IsFarmManagerRole],
        "partial_update": [IsAdminRole, IsFarmManagerRole],
        "destroy": [IsAdminRole, IsFarmManagerRole],
        "default": [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action["default"]
        )

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    # -------------------------
    # LIST (supports ?planting=ID)
    # -------------------------
    def list(self, request):
        try:
            queryset = self.get_queryset()
            planting_id = request.query_params.get("planting")
            if planting_id:
                queryset = queryset.filter(planting_id=planting_id)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "error": False,
                "message": "Crop harvest list",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # CREATE
    # -------------------------
    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Crop harvest created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # RETRIEVE
    # -------------------------
    def retrieve(self, request, pk=None):
        harvest = get_object_or_404(CropHarvest, pk=pk)
        serializer = self.get_serializer(harvest)
        return Response({
            "error": False,
            "message": "Crop harvest retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    # -------------------------
    # UPDATE / PARTIAL UPDATE
    # -------------------------
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        pk = kwargs.get("pk")

        try:
            harvest = get_object_or_404(CropHarvest, pk=pk)
            serializer = self.get_serializer(
                harvest,
                data=request.data,
                partial=partial
            )

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Crop harvest updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # DELETE
    # -------------------------
    def destroy(self, request, pk=None):
        try:
            harvest = get_object_or_404(CropHarvest, pk=pk)
            harvest.delete()
            return Response({
                "error": False,
                "message": "Crop harvest deleted successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Irrigation viewSet
class IrrigationScheduleViewSet(viewsets.ModelViewSet):
    queryset = IrrigationSchedule.objects.order_by("-id")
    serializer_class = IrrigationScheduleSerializer

    permission_classes_by_action = {
        "create": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "list": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "retrieve": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "update": [IsAdminRole, IsFarmManagerRole],
        "partial_update": [IsAdminRole, IsFarmManagerRole],
        "destroy": [IsAdminRole, IsFarmManagerRole],
        "default": [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action["default"]
        )

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return any(p().has_permission(request, view) for p in perms)

        return [AnyPermission()]

    # -------------------------
    # LIST (supports ?planting=ID)
    # -------------------------
    def list(self, request):
        try:
            queryset = self.get_queryset()
            planting_id = request.query_params.get("planting")
            if planting_id:
                queryset = queryset.filter(planting_id=planting_id)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "error": False,
                "message": "Irrigation schedule list",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # CREATE
    # -------------------------
    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Irrigation schedule created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # RETRIEVE
    # -------------------------
    def retrieve(self, request, pk=None):
        irrigation = get_object_or_404(IrrigationSchedule, pk=pk)
        serializer = self.get_serializer(irrigation)
        return Response({
            "error": False,
            "message": "Irrigation schedule retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    # -------------------------
    # UPDATE / PARTIAL UPDATE
    # -------------------------
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        pk = kwargs.get("pk")

        try:
            irrigation = get_object_or_404(IrrigationSchedule, pk=pk)
            serializer = self.get_serializer(
                irrigation,
                data=request.data,
                partial=partial
            )

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Irrigation schedule updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # DELETE
    # -------------------------
    def destroy(self, request, pk=None):
        try:
            irrigation = get_object_or_404(IrrigationSchedule, pk=pk)
            irrigation.delete()
            return Response({
                "error": False,
                "message": "Irrigation schedule deleted successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Fertilizer viewSet
class FertilizerApplicationViewSet(viewsets.ModelViewSet):
    queryset = FertilizerApplication.objects.select_related("planting").order_by("-id")
    serializer_class = FertilizerApplicationSerializer

    permission_classes_by_action = {
        "create": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "list": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "retrieve": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "update": [IsAdminRole, IsFarmManagerRole],
        "partial_update": [IsAdminRole, IsFarmManagerRole],
        "destroy": [IsAdminRole, IsFarmManagerRole],
        "default": [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action["default"]
        )

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return any(p().has_permission(request, view) for p in perms)

        return [AnyPermission()]

    # -------------------------
    # LIST (supports ?planting=ID)
    # -------------------------
    def list(self, request):
        try:
            queryset = self.get_queryset()
            planting_id = request.query_params.get("planting")
            if planting_id:
                queryset = queryset.filter(planting_id=planting_id)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "error": False,
                "message": "Fertilizer application list",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # CREATE
    # -------------------------
    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Fertilizer application created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # RETRIEVE
    # -------------------------
    def retrieve(self, request, pk=None):
        application = get_object_or_404(FertilizerApplication, pk=pk)
        serializer = self.get_serializer(application)
        return Response({
            "error": False,
            "message": "Fertilizer application retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    # -------------------------
    # UPDATE / PARTIAL UPDATE
    # -------------------------
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        pk = kwargs.get("pk")

        try:
            application = get_object_or_404(FertilizerApplication, pk=pk)
            serializer = self.get_serializer(
                application,
                data=request.data,
                partial=partial
            )

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Fertilizer application updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # DELETE
    # -------------------------
    def destroy(self, request, pk=None):
        try:
            application = get_object_or_404(FertilizerApplication, pk=pk)
            application.delete()
            return Response({
                "error": False,
                "message": "Fertilizer application deleted successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Pesticide viewSet
class PesticideApplicationViewSet(viewsets.ModelViewSet):
    queryset = PesticideApplication.objects.select_related("planting").order_by("-id")
    serializer_class = PesticideApplicationSerializer

    permission_classes_by_action = {
        "create": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "list": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "retrieve": [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        "update": [IsAdminRole, IsFarmManagerRole],
        "partial_update": [IsAdminRole, IsFarmManagerRole],
        "destroy": [IsAdminRole, IsFarmManagerRole],
        "default": [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(
            self.action,
            self.permission_classes_by_action["default"]
        )

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return any(p().has_permission(request, view) for p in perms)

        return [AnyPermission()]

    # -------------------------
    # LIST (supports ?planting=ID)
    # -------------------------
    def list(self, request):
        try:
            queryset = self.get_queryset()
            planting_id = request.query_params.get("planting")
            if planting_id:
                queryset = queryset.filter(planting_id=planting_id)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "error": False,
                "message": "Pesticide application list",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # CREATE
    # -------------------------
    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Pesticide application created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # RETRIEVE
    # -------------------------
    def retrieve(self, request, pk=None):
        application = get_object_or_404(PesticideApplication, pk=pk)
        serializer = self.get_serializer(application)
        return Response({
            "error": False,
            "message": "Pesticide application retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    # -------------------------
    # UPDATE / PARTIAL UPDATE
    # -------------------------
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        pk = kwargs.get("pk")

        try:
            application = get_object_or_404(PesticideApplication, pk=pk)
            serializer = self.get_serializer(
                application,
                data=request.data,
                partial=partial
            )

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Pesticide application updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "error": True,
                "message": "Validation failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    # -------------------------
    # DELETE
    # -------------------------
    def destroy(self, request, pk=None):
        try:
            application = get_object_or_404(PesticideApplication, pk=pk)
            application.delete()
            return Response({
                "error": False,
                "message": "Pesticide application deleted successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

