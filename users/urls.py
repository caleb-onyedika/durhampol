from django.urls import path
from .views import *


urlpatterns = [
    path('admin-signup/', admin_signup, name='admin-signup'),
    path('signup/', user_signup, name='user-signup'),
    path('login/', login_user, name='login'),
    path('logout/', logout_user, name='logout'),
    path('users/', users_list, name='users-list'),
    path('admin-users/', admins_list, name='admins-list'),


    path('approve_user/<int:user_id>/', approve_user, name='approve-user'),
    path('decline_user/<int:user_id>/', decline_user, name='decline-user'),
    path('delete_user/<int:user_id>/', delete_user, name='delete-user'),

    path('reset/<uidb64>/<token>/', password_reset_confirm, name='password-reset-confirm'),
    path('password_reset/', reset_password, name='password-reset'),

    path('verify-email/<str:uidb64>/<str:token>/', verify_email, name='verify-email'),

    path("profile/", profile, name="profile"),
]
