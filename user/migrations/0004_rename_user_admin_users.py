# Generated by Django 5.0.2 on 2024-02-21 16:26

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0003_message_alter_user_admin_name'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='user',
            new_name='Admin_users',
        ),
    ]
