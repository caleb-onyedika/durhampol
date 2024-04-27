# Generated by Django 5.0.3 on 2024-03-20 22:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0004_customuseraccount_is_approved_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuseraccount',
            name='is_approved',
            field=models.BooleanField(choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Declined', 'Declined')], default='Pending', max_length=20),
        ),
    ]
