# Generated by Django 5.0.2 on 2024-02-23 07:43

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0004_rename_user_admin_users'),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('P_name', models.CharField(max_length=100000)),
                ('P_price', models.CharField(max_length=1000000)),
                ('P_description', models.CharField(max_length=100000000)),
                ('P_picture', models.ImageField(upload_to='product_pictures/')),
                ('P_category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.category')),
            ],
        ),
        migrations.DeleteModel(
            name='Admin_users',
        ),
    ]
