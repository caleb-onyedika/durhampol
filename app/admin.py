from django.contrib import admin
from .models import Incident, IncidentAccess, ViewCrimeSceneRequest
# Register your models here.
admin.site.register(Incident)
admin.site.register(IncidentAccess)
admin.site.register(ViewCrimeSceneRequest)
