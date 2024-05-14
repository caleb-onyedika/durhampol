from django.shortcuts import render, redirect
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth import authenticate, login, logout
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import check_password
from datetime import datetime, date
from .models import IsApprovedOptions
from django.views.decorators.cache import cache_page
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.hashers import check_password

User = get_user_model()


# logout view
def logout_user(request):
    logout(request)

    return redirect(reverse('login'))


def admin_signup(request):
    context = {
        'title': 'Admin Sign Up',
    }
    if request.method == "POST":
        context = {'has_error': False, 'data': request.POST, 'title': 'Sign Up'}
        first_name = request.POST.get('first-name').strip()
        last_name = request.POST.get('last-name').strip()
        email = request.POST.get('email').strip()
        password = request.POST.get('password').strip()
        password2 = request.POST.get('confirm-password').strip()

        if len(password) < 6:
            messages.add_message(request, messages.ERROR,
                                 'Password should be at least 6 characters')
            return render(request, 'admin-signup.html', context)

        if password != password2:
            context['is_sweet_alert'] = True
            messages.error(request,
                           'Password mismatch')
            return render(request, 'admin-signup.html', context)

        if not validate_email(email):
            context['is_sweet_alert'] = True

            messages.add_message(request, messages.ERROR,
                                 'Enter a valid email address')
            return render(request, 'admin-signup.html', context)

        if User.objects.filter(email=email).exists():
            context['is_sweet_alert'] = True
            messages.error(request,
                           'Email is taken, choose another one')
            return render(request, 'admin-signup.html', context)

        if context['has_error']:
            return render(request, 'admin-signup.html', context)

        if not context['has_error']:
            user = User.objects.create_superuser(email=email, password=password)
            user.first_name = first_name
            user.last_name = last_name
            user.is_approved = IsApprovedOptions.approved
            user.save()

            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            mydict = {'name': user.first_name, 'token': token, 'uidb64': uidb64}
            html_template = 'emails/email-verification.html'
            html_message = render_to_string(html_template, context=mydict)
            subject = 'Confirm Email Adress'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user.email]
            message = EmailMessage(subject, html_message,
                                   email_from, recipient_list)
            message.content_subtype = 'html'
            # message.send()

            request.session['is_sweet_alert'] = True

            messages.success(request, 'Your registration was successful, please confirm your email before logging in.')
            return redirect('login')
    return render(request, 'admin-signup.html', context)


def user_signup(request):
    context = {
        'title': 'User Sign Up',
    }
    if request.method == "POST":
        context = {'has_error': False, 'data': request.POST, 'title': 'Sign Up'}
        first_name = request.POST.get('first-name').strip()
        last_name = request.POST.get('last-name').strip()
        email = request.POST.get('email').strip()
        dob = request.POST.get('dob')
        zipcode = request.POST.get('zipcode')
        address = request.POST.get('address')
        image = request.FILES['image']
        id_back = request.FILES['id-back']
        id_front = request.FILES['id-front']
        password = request.POST.get('password').strip()
        password2 = request.POST.get('confirm-password').strip()

        if len(password) < 6:
            context['is_sweet_alert'] = True
            messages.add_message(request, messages.ERROR,
                                 'Password should be at least 6 characters')
            return render(request, 'user-signup.html', context)

        if password != password2:
            context['is_sweet_alert'] = True
            messages.add_message(request, messages.ERROR,
                                 'Password mismatch')
            return render(request, 'user-signup.html', context)

        if not validate_email(email):
            context['is_sweet_alert'] = True
            messages.add_message(request, messages.ERROR,
                                 'Enter a valid email address')
            return render(request, 'user-signup.html', context)

        if User.objects.filter(email=email).exists():
            context['is_sweet_alert'] = True
            messages.add_message(request, messages.ERROR,
                                 'Email is taken, choose another one')
            return render(request, 'user-signup.html', context)

        if context['has_error']:
            return render(request, 'user-signup.html', context)

        if not context['has_error']:
            user = User.objects.create_user(email=email)
            user.set_password(password)
            user.first_name = first_name
            user.last_name = last_name
            user.dob = dob
            user.zipcode = zipcode
            user.address = address
            user.id_back = id_back
            user.id_front = id_front
            user.image = image
            user.save()

            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.id))

            mydict = {'name': user.first_name, 'token': token, 'uidb64': uidb64}
            html_template = 'emails/email-verification.html'
            html_message = render_to_string(html_template, context=mydict)
            subject = 'Confirm Email Adress'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user.email]
            message = EmailMessage(subject, html_message,
                                   email_from, recipient_list)
            message.content_subtype = 'html'
            # message.send()

            request.session['is_sweet_alert'] = True
            messages.success(request, 'Your registration was successful, please confirm your email before logging in.')

            return redirect('login')
    return render(request, 'user-signup.html', context)


def login_user(request):
    context = {
        'title': "Login"
    }

    if request.method == 'POST':
        context = {'data': request.POST, 'title': 'Login'}
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not validate_email(email):
            messages.add_message(request, messages.ERROR,
                                 'Please enter a valid email address and try again')
            return render(request, 'login.html', context, status=401)

        user = authenticate(request, email=email, password=password)

        if not user:
            context['is_sweet_alert'] = True
            messages.error(request, 'Invalid credentials, try again')
            return render(request, 'login.html', context, status=401)

        if user.is_approved == IsApprovedOptions.pending or user.is_approved == IsApprovedOptions.declined:
            context['is_sweet_alert'] = True
            messages.error(request, 'Your account is inactive, please contact support for approval')
            return render(request, 'login.html', context)

        # if not user.is_email_verified:
        #     context['is_sweet_alert'] = True
        #     messages.error(request, 'Please verify your email address')
        #     return render(request, 'login.html', context)

        login(request, user)
        return redirect(reverse('dashboard'))
    is_sweet_alert = request.session.get('is_sweet_alert', False)
    if is_sweet_alert:
        context['is_sweet_alert'] = True
    return render(request, 'login.html', context)


def password_reset_confirm(request, uidb64, token):
    context = {
        'title': 'Reset Password',
    }
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(id=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    # if user and default_token_generator.check_token(user, token):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm-password')

        if password != confirm_password:
            messages.add_message(request, messages.ERROR,
                                 f'Password mismatch')
            return render(request, 'password-reset-confirm.html')

        user.set_password(password)
        user.save()
        request.session['is_sweet_alert'] = True
        messages.success(request,
                         "You've successfully changed your password, please log in")
        return redirect('login')

    return render(request, 'password-reset-confirm.html', context)


def reset_password(request):
    context = {
        'title': 'Forgot Password?',
    }
    if request.method == 'POST':
        email = request.POST.get('email')
        if not validate_email(email):
            messages.add_message(request, messages.ERROR,
                                 'Please enter your email address')
            return render(request, 'password-reset-form.html', status=401)
        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            user = None

        if not user:
            messages.add_message(request, messages.ERROR,
                                 f"Please, there's no account associated with {email}")
            return render(request, 'password-reset-form.html', status=401)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        mydict = {'token': token, 'uid': uid}
        html_template = 'emails/password-reset-email.html'
        html_message = render_to_string(html_template, context=mydict)
        subject = 'Reset Password'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [email]
        message = EmailMessage(subject, html_message,
                               email_from, recipient_list)
        message.content_subtype = 'html'
        # message.send()

        context = {
            'title': 'Email Sent',
        }
        return render(request, 'password-reset-link-sent.html', context)

    return render(request, 'password-reset-form.html', context)


# approve/activate user
@login_required
def approve_user(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        user.is_approved = IsApprovedOptions.approved
        user.save()
        request.session['is_sweet_alert'] = True
        messages.success(request, f"{user.first_name} account was successfully activated")
        return redirect('users-list')

    except User.DoesNotExist:
        request.session['is_sweet_alert'] = True
        messages.error(request, "User does not exist")
        return redirect('users-list')


# deactivate/decline user
@login_required
def decline_user(request, user_id):
    current_user = request.user
    if current_user.is_staff:
        try:
            user = User.objects.get(id=user_id)
            user.is_approved = IsApprovedOptions.declined
            user.save()
            request.session['is_sweet_alert'] = True
            messages.success(request, f"{user.first_name} account was successfully deactivated")
            return redirect('users-list')

        except User.DoesNotExist:
            request.session['is_sweet_alert'] = True
            messages.error(request, "User does not exist")
            return redirect('users-list')
    else:
        messages.error(request, "Unauthorized Operation")
        return redirect('dashboard')


# delete user
@login_required
def delete_user(request, user_id):
    current_user = request.user
    if current_user.is_staff:
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            request.session['is_sweet_alert'] = True
            messages.error(request, f"{user.first_name} account was successfully deleted")
            return redirect('users-list')

        except User.DoesNotExist:
            request.session['is_sweet_alert'] = True
            messages.error(request, "User does not exist")
            return redirect('users-list')
    else:
        messages.error(request, "Unauthorized Operation")
        return redirect('dashboard')


def users_list(request):
    current_user = request.user
    if current_user.is_staff:
        users = User.objects.filter(is_staff=False)
        context = {
            'title': 'Users List',
            'users': users
        }
        is_sweet_alert = request.session.get('is_sweet_alert', False)
        if is_sweet_alert:
            context['is_sweet_alert'] = True
        return render(request, 'user-list.html', context)
    else:
        messages.error(request, "Unauthorized Operation")
        return redirect('dashboard')


def admins_list(request):
    current_user = request.user
    if current_user.is_staff:
        users = User.objects.filter(is_staff=True)
        context = {
            'title': 'Admins List',
            'users': users
        }
        is_sweet_alert = request.session.get('is_sweet_alert', False)
        if is_sweet_alert:
            context['is_sweet_alert'] = True
        return render(request, 'admin-list.html', context)
    else:
        messages.error(request, "Unauthorized Operation")
        return redirect('dashboard')


def verify_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(id=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user and default_token_generator.check_token(user, token):
        user.is_email_verified = True
        user.save()

        request.session['is_sweet_alert'] = True
        messages.success(request,
                         'Your email was successfully verified')
        login(request, user)
        return redirect('home')
    else:
        request.session['is_sweet_alert'] = True
        messages.error(request,
                       'Your email verification failed.')
        return redirect('home')


@login_required
def profile(request):
    current_user = request.user
    context = {
        'title': 'Profile',
        'user': current_user,
    }

    if request.method == "POST" and "update" in request.POST:
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')

        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.save()
        messages.success(request, 'Your profile was successfully updated')
        return redirect('profile')

    if request.method == "POST" and "change-password" in request.POST:
        old_password = request.POST.get('old-password')
        new_password = request.POST.get('new-password')
        confirm_password = request.POST.get('confirm-password')

        if not check_password(old_password, current_user.password):
            messages.error(request, 'Your current password is in correct.')
            return render(request, 'profile.html', context)

        if new_password != confirm_password:
            messages.add_message(request, messages.ERROR,
                                 f'Password mismatch')
            return render(request, 'profile.html', context)

        current_user.set_password(new_password)
        current_user.save()
        messages.success(request, 'You successfully changed your password')
        return render(request, 'profile.html', context)

    return render(request, 'profile.html', context)
