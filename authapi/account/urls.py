
from django.urls import path
from account import views
from account.views import UserRegistrationView,UserLoginView,UserProfileView,UserChangePasswordView,SendPasswordResetEmailView,UserPasswordResetView

urlpatterns = [
    path('reg/', UserRegistrationView.as_view(), name='reg'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password-email/', UserPasswordResetView.as_view(), name='reset-password-email'),
]
