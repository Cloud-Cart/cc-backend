import uuid

from django.contrib.auth.models import AbstractUser
from django.db.models import UUIDField, BooleanField, CharField, EmailField, DateTimeField
from django.utils.translation import gettext_lazy as _

from Users.managers import UserManager


class User(AbstractUser):
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = CharField(_("First Name"), max_length=150, blank=True)
    last_name = CharField(_("Last Name"), max_length=150, blank=True)
    is_staff = BooleanField(
        _("Staff Status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )
    is_registration_completed = BooleanField(
        _("Registration Completed"),
        default=False,
    )
    email = EmailField(_("Email Address"), unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [
        "first_name",
        "last_name",
    ]
    username = None
    password = None
    _save_auth = False
    objects = UserManager()

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def set_password(self, raw_password):
        r = self.authentication.set_password(raw_password)
        self._save_auth = True
        return r

    def check_password(self, raw_password):
        return self.authentication.check_password(raw_password)

    async def acheck_password(self, raw_password):
        return await self.authentication.acheck_password(raw_password)

    def set_unusable_password(self):
        r = self.authentication.set_unusable_password()
        self._save_auth = True
        return r

    def has_usable_password(self):
        return self.authentication.has_usable_password()

    def save(self, *args, save_auth=False, **kwargs):
        r = super().save(*args, **kwargs)
        if self._save_auth or save_auth:
            self.authentication.save()
            self._save_auth = False
        return r
