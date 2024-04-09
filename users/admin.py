from django.contrib import admin
from .models import CustomUserAccount

class  CustomUserAccountAdmin(admin.ModelAdmin):
    list_display = ('email','is_staff')

# Register your models here.
admin.site.register(CustomUserAccount, CustomUserAccountAdmin)