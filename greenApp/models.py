from decimal import Decimal

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone

from greenProject import settings


# Custom User Manager
class UserAccountManager(BaseUserManager):
    def create_user(self, email, name, role, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")
        if not role:
            raise ValueError("Users must have a role")

        email = self.normalize_email(email)
        user = self.model(email=email, name=name, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None, **extra_fields):
        user = self.create_user(
            email=email,
            name=name,
            role=UserAccount.Role.SUPER_ADMIN,
            password=password,
            **extra_fields
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


# Custom User Model
class UserAccount(AbstractBaseUser, PermissionsMixin):
    class Role(models.TextChoices):
        SUPER_ADMIN = "super_admin", "Super Admin"
        FARM_ADMIN = "farm_admin", "Farm Admin"
        AGROVET = "agrovet", "Agrovet"
        VET = "vet", "Vet"
        FARM_WORKER = "farm_worker", "Farm Worker"

    email = models.EmailField(unique=True)
    name = models.CharField(max_length=150)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.FARM_WORKER)
    phone = models.CharField(max_length=20, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserAccountManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    def __str__(self):
        return f"{self.name} ({self.role})"


# Role Model
class TeamRoles(models.Model):
    id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=150)
    role_description = models.TextField(null=True, blank=True)
    permissions = models.JSONField(default=dict, blank=True)
    added_on = models.DateTimeField(default=timezone.now)
    objects = models.Manager()

    def __str__(self):
        return self.role_name


# Farm model
class Farm(models.Model):
    id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE)
    farm_name = models.CharField(max_length=150)
    location = models.CharField(max_length=255)
    farm_size = models.CharField(max_length=255, null=True, blank=True)
    farm_number = models.CharField(max_length=255, null=True, blank=True)
    added_on = models.DateTimeField(default=timezone.now)
    objects = models.Manager()

    def __str__(self):
        return self.farm_name


# Notification Preference Model
class NotificationPreference(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notification_preferences"
    )
    low_stock_alerts = models.BooleanField(default=False)
    leave_requests = models.BooleanField(default=False)
    payment_reminders = models.BooleanField(default=False)
    health_reminders = models.BooleanField(default=False)
    system_updates = models.BooleanField(default=False)

    updated_at = models.DateTimeField(auto_now=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.user.email} Preferences"


# Notifications Model
class Notification(models.Model):
    TYPE_CHOICES = [
        ("alert", "Alert"),
        ("warning", "Warning"),
        ("info", "Info"),
        ("success", "Success"),
    ]

    CATEGORY_CHOICES = [
        ("inventory", "Inventory"),
        ("team", "Team"),
        ("finance", "Finance"),
        ("general", "General"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications"
    )
    title = models.CharField(max_length=255)
    message = models.TextField()
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, default="info")
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default="general")
    read = models.BooleanField(default=False)
    added_on = models.DateTimeField(default=timezone.now)
    objects = models.Manager()

    def __str__(self):
        return f"{self.title} - {self.user.email}"

    class Meta:
        ordering = ["-added_on"]


# Team Members Model
class TeamMember(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        ON_LEAVE = "on_leave", "OnLeave"
        SUSPENDED = "suspended", "Suspended"

    id = models.AutoField(primary_key=True)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=150)
    phone = models.CharField(max_length=20, blank=True, null=True)
    role = models.ForeignKey(TeamRoles,  on_delete=models.CASCADE, related_name="role")
    user = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name="team_members")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    password = models.CharField(max_length=255)  # store hashed password
    is_active = models.BooleanField(default=True)
    added_on = models.DateTimeField(default=timezone.now)
    objects = models.Manager()

    def __str__(self):
        return f"{self.name} ({self.role})"


# Leave Request Model
class LeaveRequest(models.Model):
    class Status(models.TextChoices):
        APPROVED = "Approved", "Approved"
        PENDING = "Pending", "Pending"
        REJECTED = "Rejected", "Rejected"

    id = models.AutoField(primary_key=True)
    team_member = models.ForeignKey(TeamMember, on_delete=models.CASCADE, related_name="leaves")
    leave_type = models.CharField(max_length=50)
    start_date = models.DateField()
    end_date = models.DateField()
    days = models.IntegerField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    added_on = models.DateTimeField(default=timezone.now)
    objects = models.Manager()

    def __str__(self):
        return f"{self.team_member.name} - {self.leave_type} ({self.status})"


# Salary Model
class Salary(models.Model):
    STATUS_PENDING = "PENDING"
    STATUS_PAID = "PAID"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_PAID, "Paid"),
    ]

    # Link to your TeamMember model as the employee
    employee = models.ForeignKey(
        TeamMember,
        on_delete=models.CASCADE,
        related_name="salaries"
    )
    role = models.CharField(max_length=150, blank=True)  # optional, can duplicate team_member.role
    monthly_salary = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    last_paid = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = models.Manager()

    class Meta:
        ordering = ["-employee__id", "role"]

    def __str__(self):
        return f"{self.employee.name} — {self.role or 'Employee'}"


# Salary Payment Model
class SalaryPayment(models.Model):
    PAYMENT_METHOD_CHOICES = [
        ("MPESA", "M-Pesa"),
        ("BANK", "Bank Transfer"),
        ("CASH", "Cash"),
        ("OTHER", "Other"),
    ]

    salary = models.ForeignKey(Salary, on_delete=models.CASCADE, related_name="payments")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    date = models.DateTimeField(default=timezone.now)
    method = models.CharField(max_length=16, choices=PAYMENT_METHOD_CHOICES, default="MPESA")
    reference = models.CharField(max_length=255, blank=True, help_text="Payment system reference / transaction id")
    success = models.BooleanField(default=False)
    metadata = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ["-date"]

    def __str__(self):
        return f"{self.salary.employee.name} — {self.amount} on {self.date.date()}"
