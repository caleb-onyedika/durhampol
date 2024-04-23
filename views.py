from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required

from users.models import IsApprovedOptions
from .models import Incident, IncidentImage, IncidentLog, ViewCrimeSceneRequest, ViewCrimeSceneRequestOptions, \
    IncidentAccess

User = get_user_model()


# Create your views here.
def home(request):
    context = {
        'title': 'Home',
    }

    is_sweet_alert = request.session.get('is_sweet_alert', False)
    if is_sweet_alert:
        context['is_sweet_alert'] = True

    return render(request, 'index.html', context)


def contact(request):
    context = {
        'title': 'Contact Us',
    }

    is_sweet_alert = request.session.get('is_sweet_alert', False)
    if is_sweet_alert:
        context['is_sweet_alert'] = True

    return render(request, 'contact.html', context)


@login_required
def add_new_crime_scene(request):
    current_user = request.user
    context = {
        'title': 'New Crime Scene'
    }

    if request.method == "POST":
        name_of_incident = request.POST.get('name-of-incident')
        nature_of_incident = request.POST.get('nature-of-incident')
        location_of_incident = request.POST.get('location-of-incident')
        weather_conditions = request.POST.get('weather-conditions')
        date = request.POST.get('date')
        time = request.POST.get('time')
        images = request.FILES.getlist('images[]')
        comments = request.POST.getlist('comments[]')

        incident = Incident.objects.create(
            user=current_user,
            name_of_incident=name_of_incident,
            nature_of_incident=nature_of_incident,
            location_of_incident=location_of_incident,
            weather_conditions=weather_conditions,
            date=date,
            time=time
        )

        for image, comment in zip(images, comments):
            incident_image = IncidentImage.objects.create(
                incident=incident,
                image=image,
                comment=comment
            )
        messages.success(request, "You just created a crime scene")
        return redirect("crime-scenes-list")
    return render(request, 'crimescene-form.html', context)


@login_required
def dashboard(request):
    current_user = request.user
    total_crime_scenes = Incident.objects.all().count()
    context = {
        'title': 'Dashboard',
        'user': current_user,
        'total_crime_scenes': total_crime_scenes
    }

    if current_user.is_staff:
        template_to_be_rendered = "admin-dashboard.html"
        context['total_users'] = User.objects.all().count()
        context['pending_users'] = User.objects.filter(is_approved=IsApprovedOptions.pending).count()
        context['pending_crime_scene_requests'] = ViewCrimeSceneRequest.objects.filter(status=ViewCrimeSceneRequestOptions.pending).count()

    else:
        incidents = Incident.objects.filter(user=current_user)
        incident_requests = ViewCrimeSceneRequest.objects.filter(incident__in=incidents,
                                                                 status=ViewCrimeSceneRequestOptions.pending)
        context['pending_crime_scene_requests'] = incident_requests.count()
        template_to_be_rendered = "user-dashboard.html"

    return render(request, template_to_be_rendered, context)


@login_required
def crime_scenes_list(request):
    current_user = request.user
    crime_scenes = Incident.objects.all().order_by('-id')
    context = {
        'user': current_user,
        'crime_scenes': crime_scenes,
        'title': 'Crime Scenes'
    }
    is_sweet_alert = request.session.get('is_sweet_alert', False)
    if is_sweet_alert:
        context['is_sweet_alert'] = True
    return render(request, 'crime-scenes.html', context)


@login_required
def crime_scene_detail(request, cs_id):
    current_user = request.user
    try:
        crime_scene = Incident.objects.get(id=cs_id)
    except Incident.DoesNotExist:
        request.session['is_sweet_alert'] = True
        messages.error(request, 'The crime scene you are trying to access does not exist')
        return redirect('crime-scenes-list')
    context = {
        'user': current_user,
        'crime_scene': crime_scene,
        'title': 'Crime Scene Detail'
    }
    if not current_user.is_staff and not current_user == crime_scene.user:
        if ViewCrimeSceneRequest.objects.filter(incident=crime_scene,
                                                requester=current_user,
                                                status=ViewCrimeSceneRequestOptions.pending).exists():
            request.session['is_sweet_alert'] = True
            messages.error(request, 'Your request to view this crime scene is still pending')
            return redirect('crime-scenes-list')

        if not IncidentAccess.objects.filter(incident=crime_scene, user=current_user).exists():
            context['crime_scene'] = None
            messages.error(request, 'Unauthorized operation')

    if request.method == 'POST':
        reason = request.POST.get('reason')
        ViewCrimeSceneRequest.objects.create(
            reason_for_visiting=reason,
            requester=current_user,
            incident=crime_scene
        )
        request.session['is_sweet_alert'] = True
        messages.success(request, 'Your request to view this crime scene has been sent')
        return redirect('crime-scenes-list')

    if context['crime_scene']:
        # creating log record
        if current_user.is_staff:
            rfv = "Admin"
        elif current_user == crime_scene.user:
            rfv = "Officer in Charge"
        else:
            vcsr = ViewCrimeSceneRequest.objects.get(incident=crime_scene,
                                                     requester=current_user,
                                                     status=ViewCrimeSceneRequestOptions.approved)
            rfv = vcsr.reason_for_visiting

        IncidentLog.objects.create(
            incident=crime_scene,
            visitor=current_user,
            officer_in_charge=crime_scene.user,
            protective_clothing_worn="N/A",
            reason_for_visiting=rfv

        )
    return render(request, 'crime-scene-detail.html', context)


@login_required
def delete_crime_scene(request, cs_id):
    current_user = request.user
    try:
        crime_scene = Incident.objects.get(id=cs_id)
        if current_user.is_staff or crime_scene.user:
            crime_scene.delete()
            messages.success(request, 'The crime scene was successfully deleted')
        else:
            messages.error(request, 'Unauthorized operation')
        return redirect('crime-scenes-list')

    except Incident.DoesNotExist:
        messages.error(request, 'The crime scene you are trying to access does not exist')
        return redirect('crime-scenes-list')


@login_required
def crime_scenes_requests(request):
    current_user = request.user
    if current_user.is_staff:
        csvr = ViewCrimeSceneRequest.objects.filter(status=ViewCrimeSceneRequestOptions.pending)
    else:
        incidents = Incident.objects.filter(user=current_user)
        incident_requests = ViewCrimeSceneRequest.objects.filter(incident__in=incidents,
                                                                 status=ViewCrimeSceneRequestOptions.pending)
        csvr = incident_requests

    context = {
        'user': current_user,
        'crime_scenes_view_requests': csvr,
        'title': 'Crime Scenes Requests'
    }
    return render(request, 'crime-scene-requests.html', context)


# approve crime scene request
@login_required
def approve_cs_request(request, csr_id):
    current_user = request.user
    request.session['is_sweet_alert'] = True
    try:
        vcsr = ViewCrimeSceneRequest.objects.get(id=csr_id)
        if current_user.is_staff or vcsr.incident.user:
            vcsr.status = ViewCrimeSceneRequestOptions.approved
            vcsr.save()
            incident_access = IncidentAccess.objects.create(
                incident=vcsr.incident,
                user=vcsr.requester
            )
            messages.success(request, f"You have successfully granted {vcsr.requester} access to this crime scene")

        else:
            messages.error(request, 'Unauthorized operation')
        return redirect('view-crime-scenes-request-list')

    except ViewCrimeSceneRequest.DoesNotExist:
        messages.error(request, "Crime Scene does not exist")
        return redirect('view-crime-scenes-request-list')


# decline crime scene request
@login_required
def decline_cs_request(request, csr_id):
    request.session['is_sweet_alert'] = True
    current_user = request.user
    try:
        vcsr = ViewCrimeSceneRequest.objects.get(id=csr_id)
        if current_user.is_staff or vcsr.incident.user:
            vcsr.status = ViewCrimeSceneRequestOptions.declined
            vcsr.save()
            messages.success(request, f"You have successfully declined {vcsr.requester} access to this crime scene")
        else:
            messages.error(request, 'Unauthorized operation')
        return redirect('view-crime-scenes-request-list')

    except ViewCrimeSceneRequest.DoesNotExist:
        messages.error(request, "Crime Scene does not exist")
        return redirect('view-crime-scenes-request-list')
