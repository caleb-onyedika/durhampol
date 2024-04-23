from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()


class ViewCrimeSceneRequestOptions(models.TextChoices):
    pending = "Pending"
    approved = "Approved"
    declined = "Declined"


# Create your models here.
class Incident(models.Model):
    """Details of Crime Scene"""

    name_of_incident = models.CharField(max_length=255)
    nature_of_incident = models.TextField()
    location_of_incident = models.CharField(max_length=255)
    date = models.DateField(default=timezone.now)
    time = models.TimeField(default=timezone.now)
    weather_conditions = models.CharField(max_length=255)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="incidents")

    def __str__(self):
        return self.name_of_incident


class IncidentImage(models.Model):
    """Images and comments associated with a crime scene"""

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='incident_images')
    comment = models.CharField(max_length=255)

    def __str__(self):
        return f"Image for {self.incident.name_of_incident}"

    class Meta:
        ordering = ['-id', ]


class IncidentLog(models.Model):
    """Keeps track of visits to the crime scene"""

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="incident_logs")
    visitor = models.ForeignKey(User, on_delete=models.CASCADE, related_name="visitor")
    officer_in_charge = models.ForeignKey(User, on_delete=models.CASCADE)
    protective_clothing_worn = models.CharField(max_length=255)
    reason_for_visiting = models.TextField()
    date = models.DateField(default=timezone.now)
    time = models.TimeField(default=timezone.now)

    def __str__(self):
        return self.name_of_incident

    class Meta:
        ordering = ['-id']


class IncidentAccess(models.Model):
    """Tracks access permissions granted to users for incidents"""

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="accesses")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="incident_accesses")

    def __str__(self):
        return f"{self.user.first_name} can access {self.incident.name_of_incident}"


class ViewCrimeSceneRequest(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="incident_request")
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name="crimescene_requests")
    reason_for_visiting = models.TextField()
    status = models.CharField(max_length=20, choices=ViewCrimeSceneRequestOptions,
                              default=ViewCrimeSceneRequestOptions.pending)
    date = models.DateField(default=timezone.now)
    time = models.TimeField(default=timezone.now)

    def __str__(self):
        return f"{self.requester.first_name} {self.requester.last_name} requested for access to {self.incident.name_of_incident}"

    class Meta:
        ordering = ['-id', ]


class Contact(models.Model):
    creation_time = models.TimeField(default=timezone.now)
    creation_date = models.DateField(default=timezone.now)
    phone = models.CharField(max_length=25)
    first_name = models.CharField(max_length=25)
    last_name = models.CharField(max_length=25)
    email = models.EmailField()
    message = models.TextField()

    def __str__(self):
        return self.user.email
