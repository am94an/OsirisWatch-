from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from predictions import views
from django.conf import settings
from django.conf.urls.static import static
from api.user_views import UserListView, UserDetailView, PermissionGroupListView, PermissionGroupDetailView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include(('accounts.urls', 'accounts'), namespace='accounts')),
    path('dashboard/', include(('dashboard.urls', 'dashboard'), namespace='dashboard')),  
    path('api/', include(('api.urls', 'api'), namespace='api')),  
    path('predictions/', include(('predictions.urls', 'predictions'), namespace='predictions')),
    path('', RedirectView.as_view(url='accounts/login/', permanent=True)),

    # User management URLs
    path('api/users/', UserListView.as_view(), name='user-list'),
    path('api/users/<int:user_id>/', UserDetailView.as_view(), name='user-detail'),
    path('api/permission-groups/', PermissionGroupListView.as_view(), name='permission-group-list'),
    path('api/permission-groups/<int:group_id>/', PermissionGroupDetailView.as_view(), name='permission-group-detail'),
]

# إضافة مسارات الوسائط
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
