from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError

from greenApp.models import TeamRoles, Farm, NotificationPreference, Notification, TeamMember, LeaveRequest, Salary, \
    SalaryPayment

User = get_user_model()


class UserCreateSerializer(serializers.ModelSerializer):
    role = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'phone', 'role', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        role = attrs.get('role', 'farm_admin')
        if role not in ['vet', 'agrovet', 'farm_admin', 'super_admin']:
            raise serializers.ValidationError("Invalid user role")

        return attrs


class CustomUserSerializer(serializers.ModelSerializer):
    last_login = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'phone', 'role', 'last_login']


class UserAccountSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = '__all__'


class TeamRolesSerializer(serializers.ModelSerializer):
    class Meta:
        model = TeamRoles
        fields = '__all__'


class FarmSerializer(serializers.ModelSerializer):
    class Meta:
        model = Farm
        fields = '__all__'
        read_only_fields = ['user_id', 'id', 'added_on']


class NotificationPreferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationPreference
        fields = '__all__'


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = "__all__"


class TeamSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    role_name = serializers.CharField(source="role.role_name", read_only=True)

    class Meta:
        model = TeamMember
        fields = '__all__'


class LeaveRequestSerializer(serializers.ModelSerializer):
    employee = serializers.CharField(source="team_member.name",read_only=True)

    class Meta:
        model = LeaveRequest
        fields = "__all__"
        read_only_fields = ["team_member", "status", "added_on", "days"]


class SalaryPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = SalaryPayment
        fields = '__all__'


class SalarySerializer(serializers.ModelSerializer):
    employee_name = serializers.SerializerMethodField()
    employee_role = serializers.SerializerMethodField()

    class Meta:
        model = Salary
        fields = [
            "id",
            "employee",
            "role",
            "monthly_salary",
            "last_paid",
            "status",
            "notes",
            "created_at",
            "updated_at",
            "employee_name",
            "employee_role",
        ]

    def get_employee_name(self, obj):
        # Return the TeamMember's name
        return obj.employee.name

    def get_employee_role(self, obj):
        # Return the TeamMember's role name
        return obj.employee.role.role_name if obj.employee.role else None


class SalaryDetailSerializer(SalarySerializer):
    payments = SalaryPaymentSerializer(source="payments", many=True, read_only=True)

    class Meta(SalarySerializer.Meta):
        fields = SalarySerializer.Meta.fields + ["payments"]
