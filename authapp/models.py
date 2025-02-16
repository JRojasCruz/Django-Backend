from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.

class CustomUser(AbstractUser):
  telefono = models.CharField(max_length=100, blank=True, null=True)
  direccion = models.CharField(max_length=100, blank=True, null=True)

  def __str__(self):
    return self.username