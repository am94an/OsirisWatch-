from django.urls import path
from .views import login_view, signup_view,forget_password,reset_password
urlpatterns = [
    path('login/', login_view, name='login'),
    path('signup/', signup_view, name='signup'),
    path('forget-password/', forget_password, name='forget_password'),
    path('reset-password/<uidb64>/<token>/', reset_password, name='reset_password'),

]
