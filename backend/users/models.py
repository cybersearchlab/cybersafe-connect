from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = (
        ('citizen', 'Citoyen'),
        ('company', 'Entreprise'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='citizen')
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    company_name = models.CharField(max_length=255, blank=True)
    sector = models.CharField(max_length=100, blank=True)

   

    def __str__(self):
        return self.email