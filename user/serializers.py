from rest_framework import serializers
from .models import Product,Admin_users
class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'

class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin_users
        exclude = ['admin_token']
    
class AdminUserGetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin_users
        exclude = ['admin_token','A_password']