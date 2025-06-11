from django.urls import path
from .views import dashboard_view,custom_logout,data_analysis,event_details,reports,help_support,user_management,settings,notification,activity
from .views import  mark_notification_as_read

urlpatterns = [
    path('', dashboard_view, name='dashboard'),
    path('logout/', custom_logout, name='logout'),
    path('data-analysis/', data_analysis, name='data_analysis'),
    path('event-details/', event_details, name='event_details'),
    path('reports/', reports, name='reports'),
    path('help-support/', help_support, name='help_support'),
    path('notification/', notification, name='notification'),
    path('activity/', activity, name='activity'),
    path('user-management/', user_management, name='user_management'),
    path('settings/', settings, name='settings'),
    path('mark_notification/<int:notification_id>/', mark_notification_as_read, name='mark_notification'),

]
