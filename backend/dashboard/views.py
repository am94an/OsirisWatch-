from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.http import JsonResponse
from accounts.models import Notification
from accounts.context_processors import user_data

def custom_logout(request):
    """Log out user and redirect to login page."""
    logout(request)
    return redirect('accounts:login')

@login_required
def mark_notification_as_read(request, notification_id):
    """Mark a notification as read via AJAX request."""
    if request.method == 'POST' and request.user.is_authenticated:
        notification = get_object_or_404(Notification, id=notification_id, user=request.user)
        notification.is_read = True
        notification.save()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)

# Dashboard views
@login_required
def dashboard_view(request):
    """Main dashboard view."""
    context = user_data(request)
    return render(request, 'pages/dashboard/dashboard.html', context)

@login_required
def data_analysis(request):
    """Data analysis view."""
    context = user_data(request)
    return render(request, 'pages/dashboard/data_analysis.html', context)

@login_required
def event_details(request):
    """Event details view."""
    context = user_data(request)
    return render(request, 'pages/dashboard/event_details.html', context)

@login_required
def reports(request):
    """Reports view."""
    context = user_data(request)
    return render(request, 'pages/dashboard/reports.html', context)

@login_required
def help_support(request):
    """Help and support view."""
    context = user_data(request)
    return render(request, 'pages/dashboard/help_support.html', context)

@login_required
def activity(request):
    """User activity view."""
    context = user_data(request)
    return render(request, 'pages/dashboard/activity.html', context)

@login_required
def notification(request):
    """Notifications view."""
    context = user_data(request)
    return render(request, 'pages/dashboard/notification.html', context)

@login_required
def user_management(request):
    """User management view."""
    context = user_data(request)
    return render(request, 'pages/dashboard/user_management.html', context)

@login_required
def settings(request):
    """Settings view."""
    context = user_data(request)
    return render(request, 'pages/dashboard/settings.html', context)
