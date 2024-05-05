from django.db.models.signals import post_save, pre_delete
from django.contrib.auth.models import User
from django.dispatch import receiver
from users.models import User, Role

@receiver(post_save, sender=User)
def set_role(sender, instance, created, **kwargs):
    if created:
        default_role = Role.objects.get(name="Default Role")
        instance.roles.add(default_role.pk)
        instance.save()