from django.db import models
from django.contrib.auth.models import AbstractUser

class Users(AbstractUser):
    email=models.EmailField("email_address",unique=True)
    is_verified=models.BooleanField(default=False)
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['username']


    def __str__(self)->str:
        return self.email
