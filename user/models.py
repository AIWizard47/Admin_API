from django.db import models
# Import the Token model from rest_framework.authtoken.models
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

# Create your models here.
class Category(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Product(models.Model):
    P_name = models.CharField(max_length=100000)
    P_price = models.CharField(max_length=1000000)
    P_description = models.CharField(max_length=100000000)
    P_category = models.ForeignKey(Category, on_delete=models.CASCADE)
    P_picture = models.ImageField(upload_to='product_pictures/')
    
    
class Message(models.Model):
    name = models.CharField(max_length=10000)
    email = models.CharField(max_length=100000)
    message = models.CharField(max_length=100000000)
    
class Admin_users(models.Model):
    A_username = models.CharField(max_length=100000)
    A_email = models.CharField(max_length=100000)
    A_password = models.CharField(max_length=100000)
    admin_token = models.ForeignKey(Token, on_delete=models.CASCADE)