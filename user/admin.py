from django.contrib import admin
from .models import Product, Category,Message , Admin_users
# Register your models here.

admin.site.register(Product)
admin.site.register(Category)
admin.site.register(Message)
admin.site.register(Admin_users)