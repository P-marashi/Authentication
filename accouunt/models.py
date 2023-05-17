from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager
from django.core.validators import MaxLengthValidator, MinLengthValidator
from django.utils.translation import gettext_lazy as _


# Create your models here.

class UserManager(BaseUserManager):

    def create_user(self, mobile, password=None):
        """
        Creates and saves a User with the given mobile and password.
        """
        if not mobile:
            raise ValueError('Users must have a mobile address')

        user = self.model(
            mobile=mobile,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, mobile, password=None):
        """
        Creates and saves a superuser with the given mobile and password.
        """
        user = self.create_user(
            mobile=mobile,
            password=password,
        )
        user.is_superuser = True
        user.is_active = True
        user.is_staff = True
        user.save(using=self._db)

        return user

class User(AbstractBaseUser, PermissionsMixin):
    mobile = models.CharField(
        _("mobile"),
        max_length=150,
        unique=True,
        help_text=_(
            "Required. 11 digit of your Phone Number."
        ),
        validators=[
            MaxLengthValidator(11),
            MinLengthValidator(11)

        ],
        error_messages={
            "unique": _("A user with that username already exists."),
        },
    )
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(
        _("is_active"),
        default=False,
        help_text=_(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts."
        ),
    )
    created_at = models.DateTimeField(_("User created_at"), default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "mobile"

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")

    def __str__(self):
        return self.mobile

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission? "
        # Simplest possible answer: Yes, always
        return self.is_superuser

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_employee(self):
        return self.is_staff and not self.is_superuser
