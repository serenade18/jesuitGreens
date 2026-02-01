from django.contrib.auth import user_logged_in, user_logged_out
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_save
from django.dispatch import receiver

from greenApp.models import MilkSale, EggSale, GoatMilkSale, CatfishSale, SalaryPayment, Medication, CalvingRecord, \
    KiddingRecord, Tasks, Inventory, Procurement, ActivityLog
from greenApp.utils.activity import log_activity


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ActivityLog.objects.create(
        actor=user,
        action="other",
        content_type=ContentType.objects.get_for_model(user),
        object_id=user.pk,
        description="User logged in",
    )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    ActivityLog.objects.create(
        actor=user,
        action="other",
        content_type=ContentType.objects.get_for_model(user),
        object_id=user.pk,
        description="User logged out",
    )


@receiver(post_save, sender=MilkSale)
@receiver(post_save, sender=EggSale)
@receiver(post_save, sender=GoatMilkSale)
@receiver(post_save, sender=CatfishSale)
def sales_activity(sender, instance, created, **kwargs):
    if created:
        log_activity(
            instance=instance,
            action="finance",
            description=f"New sale recorded for {instance.customer.name}",
            metadata={
                "amount": instance.total_amount,
                "status": instance.status
            }
        )


@receiver(post_save, sender=SalaryPayment)
def salary_payment_activity(sender, instance, created, **kwargs):
    if created and instance.success:
        log_activity(
            instance=instance.salary,
            action="payment",
            description=f"Salary paid to {instance.salary.employee.name}",
            metadata={
                "amount": str(instance.amount),
                "method": instance.method,
                "reference": instance.reference
            }
        )


@receiver(post_save, sender=Medication)
@receiver(post_save, sender=CalvingRecord)
@receiver(post_save, sender=KiddingRecord)
def animal_health_activity(sender, instance, created, **kwargs):
    if created:
        log_activity(
            instance=instance.animal,
            action="health",
            description=f"{sender.__name__} recorded for {instance.animal}",
        )


@receiver(post_save, sender=Inventory)
@receiver(post_save, sender=Procurement)
def inventory_activity(sender, instance, created, **kwargs):
    log_activity(
        instance=instance,
        action="inventory",
        description=f"{sender.__name__} {'added' if created else 'updated'}",
        metadata={
            "item": getattr(instance, "item", None),
            "quantity": getattr(instance, "current_stock", None),
        }
    )


@receiver(post_save, sender=Tasks)
def task_activity(sender, instance, created, **kwargs):
    log_activity(
        instance=instance,
        action="task",
        description=f"Task '{instance.title}' {'created' if created else 'updated'}",
        metadata={"status": instance.status}
    )


@receiver(post_save)
def global_create_update_logger(sender, instance, created, **kwargs):
    if sender == ActivityLog:
        return

    if sender._meta.app_label in (
        "auth", "admin", "contenttypes", "sessions"
    ):
        return

    EXCLUDED_MODELS = {
        "milksale", "eggsale", "goatmilksale", "catfishsale",
        "salarypayment", "medication", "calvingrecord",
        "kiddingrecord", "inventory", "procurement", "tasks"
    }

    if sender._meta.model_name in EXCLUDED_MODELS:
        return

    log_activity(
        instance=instance,
        action="create" if created else "update",
        description=f"{sender.__name__} {'created' if created else 'updated'}",
    )