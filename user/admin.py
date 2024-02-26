from django.contrib import admin
from .models import Product, Category,Message , Admin_users , CountryCode , PhoneNumber
# Register your models here. 

admin.site.register(Product)
admin.site.register(Category)
admin.site.register(Message)
admin.site.register(Admin_users)
admin.site.register(CountryCode)
admin.site.register(PhoneNumber)
