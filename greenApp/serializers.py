import calendar
from unicodedata import category
from datetime import date

from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from greenApp.models import TeamRoles, Farm, NotificationPreference, Notification, TeamMember, LeaveRequest, Salary, \
    SalaryPayment, DairyCattle, MilkCollection, MapDrawing, PoultryBatch, CalvingRecord, Medication, EggCollection, \
    GoatMilkCollection, DairyGoat, KiddingRecord, MortalityRecord, MilkSale, Customers, GoatMilkSale, EggSale, Orders, \
    Expense, RecurringExpense, Tasks, BillPayment, Procurement, Inventory, Payment, Rabbit, Pond, CatfishBatch, \
    CatfishSale, FeedingSchedule, FeedingRecord, DairyCattleFeedingSchedule, DairyCattleFeedingRecord, \
    DairyGoatFeedingSchedule, DairyGoatFeedingRecord, BirdsFeedingSchedule, BirdsFeedingRecord, MpesaPayment, \
    FarmVisitBooking, FarmPlants, Plot, CropPlanting, CropHarvest, IrrigationSchedule, FertilizerApplication, \
    PesticideApplication

User = get_user_model()


class CustomTokenObtainPairSerializer(serializers.Serializer):
    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        login = attrs.get("username")
        password = attrs.get("password")

        if not login or not password:
            raise serializers.ValidationError("Both login and password are required.")

        user = authenticate(
            request=self.context.get("request"),
            username=login,
            password=password
        )

        if not user:
            raise serializers.ValidationError("Invalid login credentials.")

        refresh = RefreshToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "name": user.name,
                "role": user.role,
            }
        }


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class UserCreateSerializer(serializers.ModelSerializer):
    role = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'username', 'phone', 'role', 'password']
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
        fields = ['id', 'email', 'name', 'username','phone', 'role', 'last_login']


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


class DairyCattleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DairyCattle
        fields = '__all__'


class MilkCollectionSerializer(serializers.ModelSerializer):
    animal_name = serializers.SerializerMethodField()
    class Meta:
        model = MilkCollection
        fields = [
            "id",
            "animal_name",
            "animal",
            "collection_date",
            "collection_time",
            "session",
            "quantity",
            "quality",
            "collected_by",
            "notes",
            "added_on"
        ]

    def get_animal_name(self, obj):
        return obj.animal.animal_name


class MapDrawingSerializer(serializers.ModelSerializer):
    class Meta:
        model = MapDrawing
        fields = '__all__'


class PoultryRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = PoultryBatch
        fields = '__all__'


class CalvingRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = CalvingRecord
        fields = "__all__"


class MedicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Medication
        fields = "__all__"


class EggCollectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = EggCollection
        fields = '__all__'


class DairyGoatSerializer(serializers.ModelSerializer):
    class Meta:
        model = DairyGoat
        fields = '__all__'


class GoatMilkCollectionSerializer(serializers.ModelSerializer):
    animal_name = serializers.ReadOnlyField(source="animal.animal_name")  # optional, to show goat name

    class Meta:
        model = GoatMilkCollection
        fields = [
            "id",
            "animal",
            "animal_name",
            "collection_date",
            "collection_time",
            "session",
            "quantity",
            "quality",
            "collected_by",
            "notes",
            "added_on",
        ]
        read_only_fields = ["added_on"]

    def get_animal_name(self, obj):
        return obj.animal.animal_name


class KiddingRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = KiddingRecord
        fields = "__all__"


class MortalityRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = MortalityRecord
        fields = "__all__"


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customers
        fields = ['id', 'name', 'phone', 'email', 'added_on']
        read_only_fields = ['added_on']


class MilkSaleSerializer(serializers.ModelSerializer):
    # Used only when creating/updating
    customer = serializers.DictField(write_only=True)

    # Returned in API responses
    customer_details = CustomerSerializer(source="customer", read_only=True)

    class Meta:
        model = MilkSale
        fields = "__all__"
        # Include customer_details in output
        extra_fields = ['customer_details']

    def validate(self, attrs):
        customer_data = self.initial_data.get("customer")

        if not customer_data:
            raise serializers.ValidationError({"customer": "This field is required."})

        if not customer_data.get("phone"):
            raise serializers.ValidationError({
                "customer": {"phone": "Phone is required"}
            })

        return attrs

    def create(self, validated_data):
        customer_data = validated_data.pop("customer")
        phone = customer_data["phone"]

        customer, created = Customers.objects.get_or_create(
            phone=phone,
            defaults={
                "name": customer_data.get("name"),
                "email": customer_data.get("email"),
            }
        )

        if not created:
            customer.name = customer_data.get("name", customer.name)
            customer.email = customer_data.get("email", customer.email)
            customer.save()

        sale = MilkSale.objects.create(customer=customer, **validated_data)

        # ALWAYS create the matching order
        Orders.objects.create(
            customer=customer,
            product_type="cow_milk",
            category="dairy",
            quantity=sale.quantity,
            unit_price=sale.price_per_liter,
            total_amount=sale.total_amount,
            status=sale.status,
            notes=sale.notes,
            milk_sale=sale
        )

        return sale


class GoatMilkSaleSerializer(serializers.ModelSerializer):
    # Used only when creating/updating
    customer = serializers.DictField(write_only=True)

    # Returned in API responses
    customer_details = CustomerSerializer(source="customer", read_only=True)

    class Meta:
        model = GoatMilkSale
        fields = "__all__"
        # Include customer_details in output
        extra_fields = ['customer_details']

    def validate(self, attrs):
        customer_data = self.initial_data.get("customer")

        if not customer_data:
            raise serializers.ValidationError({"customer": "This field is required."})

        if not customer_data.get("phone"):
            raise serializers.ValidationError({
                "customer": {"phone": "Phone is required"}
            })

        return attrs

    def create(self, validated_data):
        customer_data = validated_data.pop("customer")
        phone = customer_data["phone"]

        customer, created = Customers.objects.get_or_create(
            phone=phone,
            defaults={
                "name": customer_data.get("name"),
                "email": customer_data.get("email"),
            }
        )

        # Update existing customer if needed
        if not created:
            customer.name = customer_data.get("name", customer.name)
            customer.email = customer_data.get("email", customer.email)
            customer.save()

        # ALWAYS create the sale
        sale = GoatMilkSale.objects.create(customer=customer, **validated_data)

        # ALWAYS create the matching order
        Orders.objects.create(
            customer=customer,
            product_type="goat_milk",
            category="dairy",
            quantity=sale.quantity,
            unit_price=sale.price_per_liter,
            total_amount=sale.total_amount,
            status=sale.status,
            notes=sale.notes,
            goatmilk_sale=sale
        )

        return sale


class EggSaleSerializer(serializers.ModelSerializer):
    # Used only when creating/updating
    customer = serializers.DictField(write_only=True)

    # Returned in API responses
    customer_details = CustomerSerializer(source="customer", read_only=True)

    class Meta:
        model = EggSale
        fields = "__all__"
        # Include customer_details in output
        extra_fields = ['customer_details']

    def validate(self, attrs):
        customer_data = self.initial_data.get("customer")

        if not customer_data:
            raise serializers.ValidationError({"customer": "This field is required."})

        if not customer_data.get("phone"):
            raise serializers.ValidationError({
                "customer": {"phone": "Phone is required"}
            })

        return attrs

    def create(self, validated_data):
        customer_data = validated_data.pop("customer")
        phone = customer_data["phone"]

        customer, created = Customers.objects.get_or_create(
            phone=phone,
            defaults={
                "name": customer_data.get("name"),
                "email": customer_data.get("email"),
            }
        )

        if not created:
            customer.name = customer_data.get("name", customer.name)
            customer.email = customer_data.get("email", customer.email)
            customer.save()

        sale = EggSale.objects.create(customer=customer, **validated_data)

        # ALWAYS create the matching order
        Orders.objects.create(
            customer=customer,
            product_type="eggs",
            category="poultry",
            quantity=sale.trays,
            unit_price=sale.price_per_tray,
            total_amount=sale.total_amount,
            status=sale.status,
            notes=sale.notes,
            egg_sale=sale
        )

        return sale


class OrdersSerializer(serializers.ModelSerializer):
    customer_name = serializers.SerializerMethodField()

    class Meta:
        model = Orders
        fields = "__all__"

    def get_customer_name(self, obj):
        # Return the TeamMember's name
        return obj.customer.name


class RecurringExpenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecurringExpense
        fields = "__all__"


class ExpenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Expense
        fields = "__all__"


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tasks
        fields = "__all__"


class BillPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = BillPayment
        fields = "__all__"


class ProcurementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Procurement
        fields = "__all__"


class InventorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Inventory
        fields = "__all__"


class PaymentSerializer(serializers.ModelSerializer):
    customer_name = serializers.SerializerMethodField()

    class Meta:
        model = Payment
        fields = "__all__"

    def get_customer_name(self, obj):
        # Return the TeamMember's name
        return obj.customer.name


class RabbitSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rabbit
        fields = '__all__'


class PondSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pond
        fields = '__all__'


class CatfishSerializer(serializers.ModelSerializer):
    pond_name = serializers.SerializerMethodField()

    class Meta:
        model = CatfishBatch
        fields = '__all__'

    def get_pond_name(self, obj):
        # Return the Pond name
        return obj.pond.name


class CatfishSaleSerializer(serializers.ModelSerializer):
    # Used only when creating/updating
    customer = serializers.DictField(write_only=True)

    # Returned in API responses
    customer_details = CustomerSerializer(source="customer", read_only=True)

    class Meta:
        model = CatfishSale
        fields = "__all__"
        # Include customer_details in output
        extra_fields = ['customer_details']

    def validate(self, attrs):
        customer_data = self.initial_data.get("customer")

        if not customer_data:
            raise serializers.ValidationError({"customer": "This field is required."})

        if not customer_data.get("phone"):
            raise serializers.ValidationError({
                "customer": {"phone": "Phone is required"}
            })

        return attrs

    def create(self, validated_data):
        customer_data = validated_data.pop("customer")
        phone = customer_data["phone"]

        customer, created = Customers.objects.get_or_create(
            phone=phone,
            defaults={
                "name": customer_data.get("name"),
                "email": customer_data.get("email"),
            }
        )

        if not created:
            customer.name = customer_data.get("name", customer.name)
            customer.email = customer_data.get("email", customer.email)
            customer.save()

        sale = CatfishSale.objects.create(customer=customer, **validated_data)

        # ALWAYS create the matching order
        Orders.objects.create(
            customer=customer,
            product_type="catfish",
            category="fish",
            quantity=sale.kilos,
            unit_price=sale.price_per_kilo,
            total_amount=sale.total_amount,
            status=sale.status,
            notes=sale.notes,
            catfish_sale=sale
        )

        return sale


class FeedingScheduleSerializer(serializers.ModelSerializer):
    batch_code = serializers.SerializerMethodField()

    class Meta:
        model = FeedingSchedule
        fields = '__all__'

    def get_batch_code(self, obj):
        return obj.batch.id


class FeedingRecordSerializer(serializers.ModelSerializer):
    batch_id = serializers.SerializerMethodField()

    class Meta:
        model = FeedingRecord
        fields = '__all__'

    def get_batch_id(self, obj):
        return obj.schedule.batch.id


class DairyCattleFeedingScheduleSerializer(serializers.ModelSerializer):
    cattle_name = serializers.SerializerMethodField()

    class Meta:
        model = DairyCattleFeedingSchedule
        fields = '__all__'

    def get_cattle_name(self, obj):
        return obj.cattle.animal_name
        # Adjust if your DairyCattle model uses a different identifier field


class DairyCattleFeedingRecordSerializer(serializers.ModelSerializer):
    schedule_info = serializers.SerializerMethodField()

    class Meta:
        model = DairyCattleFeedingRecord
        fields = '__all__'

    def get_schedule_info(self, obj):
        return {
            "schedule_id": obj.schedule.id,
            "feed_type": obj.schedule.feed_type,
            "cattle_id": obj.schedule.cattle.id,
        }


class DairyGoatFeedingScheduleSerializer(serializers.ModelSerializer):
    goat_name = serializers.SerializerMethodField()

    class Meta:
        model = DairyGoatFeedingSchedule
        fields = '__all__'

    def get_goat_name(self, obj):
        return obj.goat.animal_name
        # Adjust if your DairyCattle model uses a different identifier field


class DairyGoatFeedingRecordSerializer(serializers.ModelSerializer):
    schedule_info = serializers.SerializerMethodField()

    class Meta:
        model = DairyGoatFeedingRecord
        fields = '__all__'

    def get_schedule_info(self, obj):
        return {
            "schedule_id": obj.schedule.id,
            "feed_type": obj.schedule.feed_type,
            "goat_id": obj.schedule.goat.id,
        }


class BirdsFeedingScheduleSerializer(serializers.ModelSerializer):
    batch_code = serializers.SerializerMethodField()

    class Meta:
        model = BirdsFeedingSchedule
        fields = '__all__'

    def get_batch_code(self, obj):
        return obj.batch.id


class BirdsFeedingRecordSerializer(serializers.ModelSerializer):
    batch_id = serializers.SerializerMethodField()

    class Meta:
        model = BirdsFeedingRecord
        fields = '__all__'

    def get_batch_id(self, obj):
        return obj.schedule.batch.id


class MpesaPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = MpesaPayment
        fields = [
            "id",
            "checkout_request_id",
            "phone_number",
            "amount",
            "status",
            "result_code",
            "result_description",
            "receipt",
            "transaction_date",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "status",
            "result_code",
            "result_description",
            "receipt",
            "transaction_date",
            "created_at",
            "updated_at",
        ]


class BookingsSerializer(serializers.ModelSerializer):
    # Optionally link booking to its payment
    payment = MpesaPaymentSerializer(read_only=True)

    class Meta:
        model = FarmVisitBooking
        fields = "__all__"


class FarmPlantsSerializer(serializers.ModelSerializer):
    class Meta:
        model = FarmPlants
        fields = "__all__"


class PlotSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plot
        fields = "__all__"


class CropPlantingSerializer(serializers.ModelSerializer):
    plot_name = serializers.CharField(source="plot.plot", read_only=True)
    plant_name = serializers.CharField(source="plant.plant_name", read_only=True)
    plot_area = serializers.DecimalField(source="plot.area", max_digits=10, decimal_places=2, read_only=True)

    class Meta:
        model = CropPlanting
        fields = "__all__"


class CropHarvestSerializer(serializers.ModelSerializer):
    class Meta:
        model = CropHarvest
        fields = "__all__"


class IrrigationScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = IrrigationSchedule
        fields = "__all__"


class FertilizerApplicationSerializer(serializers.ModelSerializer):
    planting_name = serializers.CharField(source="planting.plant.plant_name", read_only=True)
    plot_name = serializers.CharField(source="planting.plot.plot", read_only=True)
    plant_name = serializers.CharField(source="planting.plant.plant_name", read_only=True)

    class Meta:
        model = FertilizerApplication
        fields = "__all__"


class PesticideApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = PesticideApplication
        fields = "__all__"
