from django.contrib.contenttypes.models import ContentType
from greenApp.models import ActivityLog
from greenApp.middleware import get_current_user


def log_activity(
    *,
    instance,
    action,
    description,
    actor=None,
    metadata=None,
):
    ActivityLog.objects.create(
        actor=actor or get_current_user(),
        action=action,
        content_type=ContentType.objects.get_for_model(instance.__class__),
        object_id=instance.pk,
        description=description,
        metadata=metadata or {},
    )

