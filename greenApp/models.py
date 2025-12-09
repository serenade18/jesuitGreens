from decimal import Decimal

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.db.models import JSONField
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


# Cattle Info
class DairyCattle(models.Model):
    ANIMAL_TYPES = [
        ("dairy", "Dairy"),
    ]

    BREED_CHOICES = [
        ("ayshire", "Ayshire"),
        ("boran", "Boran"),
        ("brown swiss", "Brown Swiss"),
        ("fleckvieh", "Fleckvieh"),
        ("gurnsey", "Gurnsey"),
        ("jersey", "Jersey"),
        ("sahiwal", "Sahiwal"),
        ("red friesian", "Red Friesian"),
        ("holstein friesian", "Holstein Friesian"),
    ]

    CATEGORY_CHOICES = [
        ("calf", "Calf (0-4 months)"),
        ("weaner", "Weaner (4-8 months)"),
        ("heifer", "Heifer (9-10 months)"),
        ("yearling", "Yearling (11-13 months)"),
        ("bulling heifer", "Bulling Heifer (14-18 months)"),
        ("incalf heifer", "Incalf Heifer"),
        ("dry", "Dry (2 months to calving)"),
        ("milker", "Milker (After Calving)"),
        ("bull", "Bull (Male calves above 3 months)"),
    ]

    animal_type = models.CharField(max_length=20, choices=ANIMAL_TYPES, default="dairy")
    animal_name = models.CharField(max_length=50, unique=True)
    breed = models.CharField(max_length=50, choices=BREED_CHOICES, blank=True, null=True)
    tag_number = models.CharField(max_length=50, blank=True, null=True, unique=True)
    birth_weight = models.DecimalField(max_digits=5, decimal_places=1, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, blank=True, null=True)
    sire = models.CharField(max_length=100, blank=True, null=True)
    grand_sire = models.CharField(max_length=100, blank=True, null=True)
    dam = models.CharField(max_length=100, blank=True, null=True)
    grand_dam = models.CharField(max_length=100, blank=True, null=True)
    lactations = models.IntegerField(blank=True, null=True)
    color = models.CharField(max_length=50, blank=True, null=True)
    source = models.CharField(max_length=100, blank=True, null=True)
    ksb_no = models.CharField(max_length=100, blank=True, null=True)
    grade = models.CharField(max_length=50, blank=True, null=True)
    milk_target = models.DecimalField(max_digits=5, decimal_places=1, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.animal_id} ({self.breed})"


# Milk Collection
class MilkCollection(models.Model):
    SESSIONS = [
        ("morning", "Morning"),
        ("afternoon", "Afternoon"),
        ("evening", "Evening"),
    ]
    QUALITIES = [
        ("excellent", "Excellent"),
        ("good", "Good"),
        ("fair", "Fair"),
        ("poor", "Poor"),
    ]

    animal = models.ForeignKey(DairyCattle, on_delete=models.CASCADE, related_name="milk_collections")
    collection_date = models.DateField()
    collection_time = models.TimeField()
    session = models.CharField(max_length=20, choices=SESSIONS)
    quantity = models.FloatField()
    quality = models.CharField(max_length=20, choices=QUALITIES)
    collected_by = models.CharField(max_length=255)
    notes = models.TextField(blank=True, null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    class Meta:
        ordering = ["-collection_date", "-collection_time"]

    def __str__(self):
        return f"{self.quantity}L from {self.animal.name} on {self.collection_date}"


# Map section
class MapDrawing(models.Model):
    DRAWING_TYPES = [
        ('polygon', 'Polygon'),
        ('polyline', 'Polyline'),
        ('marker', 'Marker')
    ]

    CATEGORY_CHOICES = [
        ('irrigation', 'Irrigation'),
        ('fencing', 'Fencing'),
        ('field', 'Field'),
        ('crop-zone', 'Crop Zone'),
    ]

    type = models.CharField(max_length=20, choices=DRAWING_TYPES)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    coordinates = JSONField()  # stores list of lat/lng objects OR single lat/lng
    area = models.FloatField(null=True, blank=True)   # for polygons
    length = models.FloatField(null=True, blank=True) # for polylines
    label = models.CharField(max_length=255)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.type} - {self.category} - {self.label}"


# Birds Model
class PoultryBatch(models.Model):
    ANIMAL_TYPES = [
        ("poultry", "Poultry"),
    ]

    CATEGORY_CHOICES = [
        ('layers', 'Layers'),
        ('broilers', 'Broilers'),
        ('improved_kienyeji', 'Improved Kienyeji'),
    ]
    animal_type = models.CharField(max_length=20, choices=ANIMAL_TYPES, default="poultry")
    category = models.CharField(
        max_length=50,
        choices=CATEGORY_CHOICES,
    )
    breed = models.CharField(max_length=100)
    age_in_days = models.PositiveIntegerField()
    number_of_chicks = models.PositiveIntegerField()
    vaccinated = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.category.title()} - {self.breed} ({self.number_of_chicks} chicks)"


# Calving Record Model
class CalvingRecord(models.Model):
    GENDER_CHOICES = [
        ("male", "Male"),
        ("female", "Female"),
    ]

    animal = models.ForeignKey(
        "DairyCattle",
        on_delete=models.CASCADE,
        related_name="calving_records"
    )
    calving_date = models.DateField()
    calf_name = models.CharField(max_length=255)
    calf_gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    birth_weight = models.DecimalField(max_digits=6, decimal_places=2)
    complications = models.TextField(blank=True, null=True)
    assistance_required = models.BooleanField(default=False)
    veterinarian = models.CharField(max_length=255, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = models.Manager()

    class Meta:
        ordering = ["-calving_date"]

    def __str__(self):
        return f"{self.animal.id} — {self.calf_name} ({self.calving_date})"


# Medication model
class Medication(models.Model):
    TREATMENT_TYPES = (
        ("antibiotic", "Antibiotic"),
        ("deworming", "Deworming"),
        ("vaccination", "Vaccination"),
        ("vitamin", "Vitamin / Supplement"),
        ("other", "Other"),
    )

    ADMINISTRATION_ROUTES = (
        ("oral", "Oral"),
        ("injection", "Injection"),
        ("topical", "Topical"),
        ("intravenous", "Intravenous"),
        ("other", "Other"),
    )

    animal = models.ForeignKey(
        "DairyCattle",
        on_delete=models.CASCADE,
        related_name="medications"
    )
    medication_name = models.CharField(max_length=255)
    treatment_type = models.CharField(max_length=50, choices=TREATMENT_TYPES)
    dosage = models.CharField(max_length=100)
    administration_route = models.CharField(max_length=50, choices=ADMINISTRATION_ROUTES)
    treatment_date = models.DateField()
    prescribed_by = models.CharField(max_length=255, null=True, blank=True)  # veterinarian or staff name
    administered_by = models.CharField(max_length=255, null=True, blank=True)
    duration_days = models.PositiveIntegerField(null=True, blank=True)
    next_dose_date = models.DateField(null=True, blank=True)
    reason = models.TextField(null=True, blank=True)
    notes = models.TextField(null=True, blank=True)
    cost = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.medication_name} - {self.animal}"


# Eggs collection model
class EggCollection(models.Model):
    batch = models.ForeignKey(
        'PoultryBatch',              # or your PoultryBatch model name
        on_delete=models.CASCADE,
        related_name='egg_collections'
    )
    collection_date = models.DateField()
    total_eggs = models.PositiveIntegerField()
    broken_eggs = models.PositiveIntegerField(null=True, blank=True, default=0)
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Batch {self.batch_id} - {self.collection_date} ({self.total_eggs} eggs)"


# Dairy Goat Info
class DairyGoat(models.Model):
    ANIMAL_TYPES = [
        ("dairy", "Dairy"),
    ]

    BREED_CHOICES = [
        ("alpine", "Alpine"),
        ("boer", "Boer"),
        ("jamunapari", "Jamunapari"),
        ("nigerian dwarf", "Nigerian Dwarf"),
        ("saanen", "Saanen"),
        ("toggenburg", "Toggenburg"),
        ("other", "Other"),
    ]

    CATEGORY_CHOICES = [
        ("kid", "Kid (0-6 months)"),
        ("doeling", "Doeling (Female kid 6-12 months)"),
        ("buckling", "Buckling (Male kid 6-12 months)"),
        ("yearling", "Yearling (12-18 months)"),
        ("bulling doe", "Bulling Doe (18-24 months)"),
        ("in-calf doe", "In-calf Doe"),
        ("dry doe", "Dry Doe (2 months to kidding)"),
        ("milker", "Milker (After Kidding)"),
        ("buck", "Buck (Adult Male)"),
    ]

    animal_type = models.CharField(max_length=20, choices=ANIMAL_TYPES, default="dairy")
    animal_name = models.CharField(max_length=50, unique=True)
    breed = models.CharField(max_length=50, choices=BREED_CHOICES, blank=True, null=True)
    tag_number = models.CharField(max_length=50, blank=True, null=True, unique=True)
    birth_weight = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, blank=True, null=True)
    sire = models.CharField(max_length=100, blank=True, null=True)
    grand_sire = models.CharField(max_length=100, blank=True, null=True)
    dam = models.CharField(max_length=100, blank=True, null=True)
    grand_dam = models.CharField(max_length=100, blank=True, null=True)
    lactations = models.IntegerField(blank=True, null=True)
    color = models.CharField(max_length=50, blank=True, null=True)
    source = models.CharField(max_length=100, blank=True, null=True)
    ksb_no = models.CharField(max_length=100, blank=True, null=True)
    grade = models.CharField(max_length=50, blank=True, null=True)
    milk_target = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.animal_name} ({self.breed})"


# Goat Milk Collection
class GoatMilkCollection(models.Model):
    SESSIONS = [
        ("morning", "Morning"),
        ("afternoon", "Afternoon"),
        ("evening", "Evening"),
    ]
    QUALITIES = [
        ("excellent", "Excellent"),
        ("good", "Good"),
        ("fair", "Fair"),
        ("poor", "Poor"),
    ]

    animal = models.ForeignKey(DairyGoat, on_delete=models.CASCADE, related_name="milk_collections")
    collection_date = models.DateField()
    collection_time = models.TimeField()
    session = models.CharField(max_length=20, choices=SESSIONS)
    quantity = models.FloatField()
    quality = models.CharField(max_length=20, choices=QUALITIES)
    collected_by = models.CharField(max_length=255)
    notes = models.TextField(blank=True, null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    class Meta:
        ordering = ["-collection_date", "-collection_time"]

    def __str__(self):
        return f"{self.quantity}L from {self.animal.animal_name} on {self.collection_date}"


# Kidding Record Model
class KiddingRecord(models.Model):
    GENDER_CHOICES = [
        ("male", "Male"),
        ("female", "Female"),
    ]

    animal = models.ForeignKey(
        "DairyGoat",
        on_delete=models.CASCADE,
        related_name="kidding_records"
    )
    kidding_date = models.DateField()
    kid_name = models.CharField(max_length=255)
    kid_gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    birth_weight = models.DecimalField(max_digits=6, decimal_places=2)
    complications = models.TextField(blank=True, null=True)
    assistance_required = models.BooleanField(default=False)
    veterinarian = models.CharField(max_length=255, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = models.Manager()

    class Meta:
        ordering = ["-kidding_date"]

    def __str__(self):
        return f"{self.animal.id} — {self.kid_name} ({self.kidding_date})"


# Chicken Mortality model
class MortalityRecord(models.Model):
    batch = models.ForeignKey(
        'PoultryBatch',  # or your PoultryBatch model name
        on_delete=models.CASCADE,
        related_name='mortalities'
    )
    date = models.DateField()
    number_of_deaths = models.PositiveIntegerField()
    cause = models.CharField(max_length=255, null=True, blank=True)
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"Mortality Record B{self.batch.id} - {self.number_of_deaths} deaths"


# Customers Model
class Customers(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255, unique=True)  # Unique
    email = models.CharField(max_length=255, null=True, blank=True)
    town = models.CharField(max_length=255, null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name}"


# Dairy milk sales model
class MilkSale(models.Model):
    STATUS = [
        ('paid', 'Paid'),
        ('pending', 'Pending'),
        ('partial', 'Partial')
    ]

    id = models.AutoField(primary_key=True)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name="milk_sales")
    quantity = models.FloatField()
    price_per_liter = models.FloatField()
    total_amount = models.FloatField()
    status = models.CharField(max_length=20, choices=STATUS)
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"Sale #{self.id} - {self.customer.name}"


# Goat milk sale
class GoatMilkSale(models.Model):
    STATUS = [
        ('paid', 'Paid'),
        ('pending', 'Pending'),
        ('partial', 'Partial')
    ]

    id = models.AutoField(primary_key=True)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name="goat_milk_sales")
    quantity = models.FloatField()
    price_per_liter = models.FloatField()
    total_amount = models.FloatField()
    status = models.CharField(max_length=20, choices=STATUS)
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"Sale #{self.id} - {self.customer.name}"


# Egg sale
class EggSale(models.Model):
    STATUS = [
        ('paid', 'Paid'),
        ('pending', 'Pending'),
        ('partial', 'Partial')
    ]

    id = models.AutoField(primary_key=True)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name="egg_sales")
    trays = models.FloatField()
    price_per_tray = models.FloatField()
    total_amount = models.FloatField()
    status = models.CharField(max_length=20, choices=STATUS)
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"Sale #{self.id} - {self.customer.name}"


# Expenses Model
class Expense(models.Model):
    CATEGORY = [
        ("repair", "Repair"),
        ("vet", "Vet"),
        ("transport", "Transport"),
        ("construction", "Construction"),
        ("maintenance", "Maintenance"),
    ]

    STATUS = [
        ("pending", "Pending"),
        ("paid", "Paid"),
        ("overdue", "Overdue"),
    ]

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, blank=True)
    category = models.CharField(max_length=20, choices=CATEGORY)
    amount = models.FloatField()
    date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS, default="paid")
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.provider_name} ({self.expense_type}) - {self.amount} KES"


# Recurring Expense
class RecurringExpense(models.Model):
    CATEGORY = [
        ("utility", "Utility"),
        ("services", "Services"),
    ]

    FREQUENCIES = [
        ("monthly", "Monthly"),
        ("quarterly", "Quarterly"),
        ("yearly", "Yearly"),
    ]

    STATUS = [
        ("pending", "Pending"),
        ("paid", "Paid"),
        ("overdue", "Overdue"),
    ]

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=20, choices=CATEGORY)
    frequency = models.CharField(max_length=20, choices=FREQUENCIES, default="monthly")
    notes = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS, default="pending")
    is_active = models.BooleanField(default=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.name} ({self.frequency})"


# Tasks model
class Tasks(models.Model):
    PRIORITY = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
    ]

    STATUS = [
        ("pending", "Pending"),
        ("in_progress", "In Progress"),
        ("completed", "Completed"),
    ]

    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    due_date = models.DateField()
    priority = models.CharField(max_length=10, choices=PRIORITY, default="medium")
    status = models.CharField(max_length=15, choices=STATUS, default="pending")
    added_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.status})"


# Bill payment model
class BillPayment(models.Model):
    id = models.AutoField(primary_key=True)
    bill_id = models.ForeignKey(
        RecurringExpense,
        on_delete=models.CASCADE,
        related_name="bill_payments"
    )
    payment_date = models.DateField()
    amount = models.FloatField()
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.bill_id} - {self.amount} KES"


# Procurement model
class Procurement(models.Model):
    CATEGORY_CHOICES = [
        ("Feed", "Feed"),
        ("Vaccine", "Vaccine"),
        ("Fertilizer", "Fertilizer"),
        ("Seeds", "Seeds"),
        ("Animal", "Animal"),
        ("Equipment", "Equipment"),
        ("Other", "Other"),
    ]

    item = models.CharField(max_length=255)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    quantity = models.FloatField()
    unit_cost = models.FloatField()
    supplier = models.CharField(max_length=255)
    purchase_date = models.DateField()
    total_cost = models.FloatField()
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.item} - {self.supplier}"


# Inventory model
class Inventory(models.Model):
    id = models.AutoField(primary_key=True)
    item = models.CharField(max_length=255)
    category = models.CharField(max_length=255)
    current_stock = models.FloatField()
    min_threshold = models.FloatField()
    unit = models.CharField(max_length=50)  # e.g. kg, pcs, bags
    unit_cost = models.FloatField()
    supplier = models.CharField(max_length=255)
    added_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.item} ({self.current_stock} {self.unit})"


# Payment model
class Payment(models.Model):
    id = models.AutoField(primary_key=True)
    order = models.ForeignKey(
        'Orders',  # Link to your Orders model
        on_delete=models.CASCADE,
        related_name="payments"
    )
    customer = models.ForeignKey(
        'Customers',
        on_delete=models.CASCADE,
        related_name="payments"
    )
    order_amount = models.FloatField()  # Total amount of the order
    payment_amount = models.FloatField()  # How much was paid
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"Payment #{self.id} for Order #{self.order.id} - Customer: {self.customer.name}"


# Rabbits Model
class Rabbit(models.Model):
    ANIMAL_TYPES = [
        ("rabbit", "Rabbit"),
    ]

    SEX_CHOICES = [
        ('buck', 'Buck'),
        ('doe', 'Doe'),
    ]

    BREED_CHOICES = [
        ("californian", "Californian"),
        ("chinchilla", "Chinchilla"),
        ("flemish giant", "Flemish Giant"),
        ("new zealand white", "New Zealand White"),
        ("kenya white", "Kenya White"),
        ("dutch", "Dutch"),
        ("angora", "Angora"),
        ("french loop", "French Loop"),
        ("other", "Other"),
    ]

    CATEGORY_CHOICES = [
        ('does', 'Does'),
        ('bucks', 'Bucks'),
        ('growers', 'Growers'),
        ('kits', 'Kits'),
    ]

    STATUS_CHOICES = [
        ('alive', 'Alive'),
        ('sold', 'Sold'),
        ('dead', 'Dead'),
        ('culled', 'Culled'),
    ]

    animal_type = models.CharField(max_length=20, choices=ANIMAL_TYPES, default="rabbit")
    animal_name = models.CharField(max_length=50, unique=True)
    sex = models.CharField(max_length=10, choices=SEX_CHOICES)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    breed = models.CharField(max_length=50, choices=BREED_CHOICES, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    father = models.ForeignKey('self', related_name='sired', on_delete=models.SET_NULL, null=True, blank=True)
    mother = models.ForeignKey('self', related_name='birthed', on_delete=models.SET_NULL, null=True, blank=True)
    cage_number = models.CharField(max_length=50, blank=True, null=True)
    vaccinated = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='alive')
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.animal_name} ({self.sex}, {self.breed})"


# Ponds Model
class Pond(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, unique=True)
    volume_liters = models.FloatField()
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return self.name


# Catfish Batch
class CatfishBatch(models.Model):
    ANIMAL_TYPES = [
        ("catfish", "Catfish"),
    ]

    id = models.AutoField(primary_key=True)   # This becomes your batch code
    animal_type = models.CharField(max_length=20, choices=ANIMAL_TYPES, default="catfish")
    pond = models.ForeignKey(
        Pond,
        on_delete=models.CASCADE,
        related_name="batches"   # Correct semantic relationship
    )
    quantity_stocked = models.IntegerField()
    average_weight_at_stocking = models.FloatField()
    stocking_date = models.DateField()
    supplier = models.CharField(max_length=100, null=True, blank=True)
    health_status = models.CharField(max_length=50, default="Healthy")
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"Batch {self.id} in {self.pond.name}"


# Catfish sales
class CatfishSale(models.Model):
    STATUS = [
        ('paid', 'Paid'),
        ('pending', 'Pending'),
        ('partial', 'Partial')
    ]

    id = models.AutoField(primary_key=True)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name="catfish_sales")
    kilos = models.FloatField()
    price_per_kilo = models.FloatField()
    total_amount = models.FloatField()
    status = models.CharField(max_length=20, choices=STATUS)
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"Sale #{self.id} - {self.customer.name}"


# All Orders
class Orders(models.Model):
    PRODUCT_TYPES = [
        ("cow_milk", "Cow Milk"),
        ("goat_milk", "Goat Milk"),
        ("eggs", "Eggs"),
        ("catfish", "Catfish"),
    ]

    STATUS = [
        ("paid", "Paid"),
        ("pending", "Pending"),
        ("partial", "Partial"),
    ]

    CATEGORY = [
        ("livestock", "Livestock"),
        ("dairy", "Dairy"),
        ("poultry", "Poultry"),
        ("crop", "Crop"),
        ("fish", "Fish"),
    ]

    id = models.AutoField(primary_key=True)
    customer = models.ForeignKey(
        Customers,
        on_delete=models.CASCADE,
        related_name="orders"
    )
    product_type = models.CharField(max_length=20, choices=PRODUCT_TYPES)
    category = models.CharField(max_length=20, choices=CATEGORY, null=True, blank=True)
    quantity = models.FloatField(null=True, blank=True)
    unit_price = models.FloatField(null=True, blank=True)
    egg_sale = models.ForeignKey(EggSale, on_delete=models.CASCADE, related_name="egg_sales", null=True, blank=True)
    milk_sale = models.ForeignKey(MilkSale, on_delete=models.CASCADE, related_name="milk_sales", null=True, blank=True)
    goatmilk_sale = models.ForeignKey(GoatMilkSale, on_delete=models.CASCADE, related_name="goatmilk_sales", null=True, blank=True)
    catfish_sale = models.ForeignKey(CatfishSale, on_delete=models.CASCADE, related_name="catfish_sales", null=True, blank=True)
    total_amount = models.FloatField()
    status = models.CharField(max_length=20, choices=STATUS)
    notes = models.TextField(null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return f"{self.product_type} sale #{self.id} - {self.customer.name}"

