from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.db import models
from validate_email import validate_email
from django.core.validators import RegexValidator
from django.db.models import TextChoices


phone_regex = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',
    message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
)


class IsApprovedOptions(TextChoices):
    pending = "Pending"
    approved = "Approved"
    declined = "Declined"


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(email, password)
        user.is_active = True
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class CustomUserAccount(AbstractUser):

    # Ensure email is unique
    email = models.EmailField(unique=True)
    username = models.CharField(default="N/A", max_length=15)
    # personal info
    id_back = models.ImageField(null=True, blank=True, upload_to="images/id_cards")
    id_front = models.ImageField(null=True, blank=True, upload_to="images/id_cards")
    dob = models.DateField(null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    zipcode = models.CharField(max_length=10, null=True, blank=True)
    image = models.ImageField(null=True, blank=True, upload_to="images/profile_pictures")
    is_approved = models.CharField(default=IsApprovedOptions.pending, max_length=20, choices=IsApprovedOptions)
    is_email_verified = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
