from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.models import User
from django.urls import reverse
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, FileResponse
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.forms import PasswordChangeForm
import random
import hashlib
import json
import os
import zipfile
import shutil
import tempfile
import datetime
from .forms import LoginForm, SignupForm, ProfileForm
from .models import (
    UserProfile, Notification, NetworkFlow, SuspiciousIP, Alert, Threat, 
    AttackType, Agent, EmailVerification, Report, BackupRecord, System_Settings
)
from .utils import generate_token, check_token


def create_profiles_for_existing_users():
    users = User.objects.all()
    for user in users:
        if not UserProfile.objects.filter(user=user).exists():
            UserProfile.objects.create(user=user, role='User', notifications=0)
            print(f"Created profile for {user.username}")

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                login(request, user)
                return redirect('dashboard:dashboard')
            else:
                messages.error(request, 'Invalid username or password')
    else:
        form = LoginForm()
    
    return render(request, 'pages/auth/login.html', {'form': form})

def signup_view(request):
    form = SignupForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save(commit=False)
        user.set_password(form.cleaned_data['password'])
        user.save()

        # Create user profile
        profile = UserProfile.objects.create(
            user=user, 
            role='User'
        )
        
        # Create welcome notification
        Notification.objects.create(
            user=user, 
            message='Welcome to the Osiris Network Security Platform!',
            notification_type='push',
            priority='medium'
        )
        
        # Send email verification
        verification_token = create_verification_token(user)
        
        messages.success(
            request, 
            'Account created successfully. Please check your email to verify your account before logging in.'
        )
        return redirect('accounts:login')

    return render(request, 'pages/auth/login.html', {'form': form})

def forget_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        try:
            user = User.objects.get(email=email)
            token = generate_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            link = f"http://127.0.0.1:8000{reverse('accounts:reset_password', kwargs={'uidb64': uid, 'token': token})}"

            send_mail(
                'Password Reset',
                f'You can reset your password using this link: {link}',
                'from@example.com',
                [user.email],
                fail_silently=False,
            )
            messages.success(request, 'Password reset link has been sent to your email.')
            return redirect('accounts:login')

        except User.DoesNotExist:
            messages.error(request, 'Email is not registered.')
            return redirect('accounts:forget_password')

    return render(request, 'pages/auth/forget.html')

def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        if not check_token(user, token):
            messages.error(request, 'The password reset link is invalid or has expired.')
            return redirect('accounts:login')

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if request.method == 'POST':
        new_password = request.POST['password']
        user.set_password(new_password)
        user.save()
        messages.success(request, 'Password successfully changed.')
        return redirect('accounts:login')

    return render(request, 'pages/auth/reset_password.html', {'user': user, 'uidb64': uidb64, 'token': token})

def user_profile_list(request):
    profiles = UserProfile.objects.all()
    data = [{"id": profile.id, "user": profile.user.username, "role": profile.role} for profile in profiles]
    return JsonResponse(data, safe=False)

def user_profile_detail(request, pk):
    profile = get_object_or_404(UserProfile, pk=pk)
    data = {
        "id": profile.id,
        "user": profile.user.username,
        "role": profile.role
    }
    return JsonResponse(data)

def create_user_profile(request):
    if request.method == "POST":
        data = json.loads(request.body)
        user = get_object_or_404(User, pk=data.get("user_id"))
        profile = UserProfile.objects.create(
            user=user,
            role=data.get("role")
        )
        return JsonResponse({"id": profile.id, "user": profile.user.username, "role": profile.role}, status=201)

def network_flow_list(request):
    flows = NetworkFlow.objects.all()
    data = [{
        "id": flow.id,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "protocol": flow.protocol,
        "threat_level": flow.threat_level,
        "created_at": flow.created_at
    } for flow in flows]
    return JsonResponse(data, safe=False)

def network_flow_detail(request, pk):
    flow = get_object_or_404(NetworkFlow, pk=pk)
    data = {
        "id": flow.id,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "threat_level": flow.threat_level,
        "created_at": flow.created_at,
        "agent": flow.agent.id if flow.agent else None
    }
    return JsonResponse(data)

def create_network_flow(request):
    if request.method == "POST":
        data = json.loads(request.body)
        agent = get_object_or_404(Agent, pk=data.get("agent_id"))
        flow = NetworkFlow.objects.create(
            flow_id=data.get("flow_id"),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol"),
            start_time=data.get("start_time"),
            packet_count=data.get("packet_count", 0),
            total_bytes=data.get("total_bytes", 0),
            threat_level=data.get("threat_level", "low")
        )
        return JsonResponse({
            "id": flow.id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "protocol": flow.protocol,
            "threat_level": flow.threat_level
        }, status=201)

def alert_list(request):
    alerts = Alert.objects.all()
    data = [{"id": alert.id, "alert_type": alert.alert_type, "severity": alert.severity} for alert in alerts]
    return JsonResponse(data, safe=False)

def alert_detail(request, pk):
    alert = get_object_or_404(Alert, pk=pk)
    data = {
        "id": alert.id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "attack_type": alert.attack_type.id if alert.attack_type else None
    }
    return JsonResponse(data)

def create_alert(request):
    if request.method == "POST":
        data = json.loads(request.body)
        flow = get_object_or_404(NetworkFlow, pk=data.get("flow_id"))
        attack_type = get_object_or_404(AttackType, pk=data.get("attack_type_id"))
        alert = Alert.objects.create(
            flow=flow,
            alert_type=data.get("alert_type"),
            severity=data.get("severity"),
            attack_type=attack_type
        )
        return JsonResponse({"id": alert.id, "alert_type": alert.alert_type, "severity": alert.severity}, status=201)

def threat_list(request):
    threats = Threat.objects.all()
    data = [{"id": threat.id, "threat_name": threat.threat_name, "threat_level": threat.threat_level} for threat in threats]
    return JsonResponse(data, safe=False)

def threat_detail(request, pk):
    threat = get_object_or_404(Threat, pk=pk)
    data = {
        "id": threat.id,
        "threat_name": threat.threat_name,
        "threat_level": threat.threat_level,
        "attack_type": threat.attack_type.id if threat.attack_type else None
    }
    return JsonResponse(data)

def create_threat(request):
    if request.method == "POST":
        data = json.loads(request.body)
        alert = get_object_or_404(Alert, pk=data.get("alert_id"))
        attack_type = get_object_or_404(AttackType, pk=data.get("attack_type_id"))
        threat = Threat.objects.create(
            alert=alert,
            threat_name=data.get("threat_name"),
            threat_level=data.get("threat_level"),
            attack_type=attack_type
        )
        return JsonResponse({"id": threat.id, "threat_name": threat.threat_name, "threat_level": threat.threat_level}, status=201)

def suspicious_ip_list(request):
    ips = SuspiciousIP.objects.all()
    data = [{"id": ip.id, "ip_address": ip.ip_address, "date": ip.date} for ip in ips]
    return JsonResponse(data, safe=False)

def suspicious_ip_detail(request, pk):
    ip = get_object_or_404(SuspiciousIP, pk=pk)
    data = {
        "id": ip.id,
        "ip_address": ip.ip_address,
        "date": ip.date,
        "alert": ip.alert.id if ip.alert else None,
        "threat": ip.threat.id if ip.threat else None
    }
    return JsonResponse(data)

def create_suspicious_ip(request):
    if request.method == "POST":
        data = json.loads(request.body)
        alert = get_object_or_404(Alert, pk=data.get("alert_id"))
        threat = get_object_or_404(Threat, pk=data.get("threat_id"))
        ip = SuspiciousIP.objects.create(
            ip_address=data.get("ip_address"),
            date=data.get("date"),
            alert=alert,
            threat=threat
        )
        return JsonResponse({"id": ip.id, "ip_address": ip.ip_address, "date": ip.date}, status=201)

@login_required
def profile_view(request):
    """View and update user profile information."""
    user = request.user
    profile = UserProfile.objects.get(user=user)
    
    if request.method == 'POST':
        form = ProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('accounts:profile')
    else:
        form = ProfileForm(instance=profile)
    
    return render(request, 'pages/profile/profile.html', {
        'form': form,
        'profile': profile
    })

@login_required
def change_password(request):
    """Allow users to change their password."""
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Update the session to prevent logging out
            update_session_auth_hash(request, user)
            
            # Update last_password_change in UserProfile
            profile = UserProfile.objects.get(user=user)
            profile.last_password_change = timezone.now()
            profile.save()
            
            messages.success(request, 'Your password was successfully updated.')
            return redirect('accounts:profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    
    return render(request, 'pages/profile/change_password.html', {
        'form': form
    })

def email_verification(request, token):
    """Verify user email with token."""
    try:
        verification = EmailVerification.objects.get(
            token=token,
            expires_at__gt=timezone.now(),
            verified=False
        )
        
        # Mark email as verified
        verification.verified = True
        verification.save()
        
        # Update user profile
        profile = UserProfile.objects.get(user=verification.user)
        profile.is_email_verified = True
        profile.save()
        
        messages.success(request, 'Your email has been verified successfully.')
        return redirect('accounts:login')
        
    except EmailVerification.DoesNotExist:
        messages.error(request, 'Invalid or expired verification link.')
        return redirect('accounts:login')

def create_verification_token(user):
    """Create and send email verification token."""
    # Delete any existing verifications
    EmailVerification.objects.filter(user=user).delete()
    
    # Create token
    token = hashlib.sha256(f"{user.email}{random.random()}".encode()).hexdigest()
    expires_at = timezone.now() + datetime.timedelta(days=2)
    
    # Save verification record
    verification = EmailVerification.objects.create(
        user=user,
        token=token,
        expires_at=expires_at
    )
    
    # Send verification email
    verification_link = f"http://127.0.0.1:8000{reverse('accounts:email_verification', kwargs={'token': token})}"
    send_mail(
        'Verify Your Email Address',
        f'Please click the link to verify your email: {verification_link}',
        'from@example.com',
        [user.email],
        fail_silently=False,
    )
    
    return token

@login_required
def download_report(request, report_id):
    """Download report in specified format."""
    report = get_object_or_404(Report, id=report_id)
    
    # Check if user has permission to access this report
    if request.user != report.user and not request.user.is_staff:
        messages.error(request, "You don't have permission to access this report.")
        return redirect('dashboard:dashboard')
    
    # If report file already exists, serve it
    if report.report_file:
        return FileResponse(report.report_file, as_attachment=True)
    
    # Generate report file based on format
    if report.report_format == 'pdf':
        # Generate PDF file (example implementation)
        # This is a placeholder - in a real app you'd use a PDF generation library
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="report_{report_id}.pdf"'
        # ... PDF generation code here ...
        return response
        
    elif report.report_format == 'csv':
        # Generate CSV file
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="report_{report_id}.csv"'
        # ... CSV generation code here ...
        return response
        
    else:  # Default text format
        response = HttpResponse(content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="report_{report_id}.txt"'
        response.write(report.content)
        return response

@login_required
def backup_system(request):
    """Create a system backup."""
    # Check if user has admin privileges
    if not request.user.is_staff:
        messages.error(request, "You don't have permission to create backups.")
        return redirect('dashboard:dashboard')
    
    try:
        # Create a temporary directory for the backup
        temp_dir = tempfile.mkdtemp()
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'backup_{timestamp}.zip'
        backup_path = os.path.join(temp_dir, backup_filename)
        
        # Create a zip file
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add database dump (example - this would normally use Django's dumpdata)
            db_dump_path = os.path.join(temp_dir, 'db_dump.json')
            os.system(f'python manage.py dumpdata > {db_dump_path}')
            zipf.write(db_dump_path, 'db_dump.json')
            
            # Add media files
            media_dir = os.path.join(settings.BASE_DIR, 'media')
            if os.path.exists(media_dir):
                for root, dirs, files in os.walk(media_dir):
                    for file in files:
                        full_path = os.path.join(root, file)
                        relative_path = os.path.relpath(full_path, settings.BASE_DIR)
                        zipf.write(full_path, relative_path)
        
        # Calculate backup size
        backup_size = os.path.getsize(backup_path)
        
        # Save the backup file to the media directory
        backup_media_dir = os.path.join(settings.MEDIA_ROOT, 'backups')
        os.makedirs(backup_media_dir, exist_ok=True)
        final_backup_path = os.path.join(backup_media_dir, backup_filename)
        shutil.move(backup_path, final_backup_path)
        
        # Create backup record
        backup_record = BackupRecord.objects.create(
            backup_file=f'backups/{backup_filename}',
            backup_size=backup_size,
            backup_type='full',
            created_by=request.user
        )
        
        # Update system settings
        system_settings = System_Settings.objects.first()
        if system_settings:
            system_settings.last_backup = timezone.now()
            system_settings.save()
        
        messages.success(request, f'Backup created successfully. Size: {backup_size/1024/1024:.2f} MB')
        return redirect('accounts:profile')
    
    except Exception as e:
        messages.error(request, f'Backup failed: {str(e)}')
        return redirect('accounts:profile')
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)

@login_required
def restore_backup(request, backup_id):
    """Restore system from a backup."""
    # Check if user has admin privileges
    if not request.user.is_staff:
        messages.error(request, "You don't have permission to restore backups.")
        return redirect('dashboard:dashboard')
    
    backup = get_object_or_404(BackupRecord, id=backup_id)
    
    # This would be a dangerous operation that should require confirmation
    if request.method == 'POST' and request.POST.get('confirm') == 'yes':
        try:
            # Create a temporary directory for restoration
            temp_dir = tempfile.mkdtemp()
            
            # Extract the backup
            with zipfile.ZipFile(backup.backup_file.path, 'r') as zipf:
                zipf.extractall(temp_dir)
            
            # Restore the database (example)
            db_dump_path = os.path.join(temp_dir, 'db_dump.json')
            if os.path.exists(db_dump_path):
                # This is a placeholder - in a real app, use loaddata or a custom restoration process
                os.system(f'python manage.py flush --no-input')
                os.system(f'python manage.py loaddata {db_dump_path}')
            
            # Restore media files
            media_dir = os.path.join(temp_dir, 'media')
            if os.path.exists(media_dir):
                # Remove existing media files
                shutil.rmtree(settings.MEDIA_ROOT, ignore_errors=True)
                os.makedirs(settings.MEDIA_ROOT, exist_ok=True)
                
                # Copy restored media files
                for root, dirs, files in os.walk(media_dir):
                    for file in files:
                        src_path = os.path.join(root, file)
                        rel_path = os.path.relpath(src_path, media_dir)
                        dst_path = os.path.join(settings.MEDIA_ROOT, rel_path)
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        shutil.copy2(src_path, dst_path)
            
            messages.success(request, 'System successfully restored from backup.')
            return redirect('accounts:profile')
            
        except Exception as e:
            messages.error(request, f'Restoration failed: {str(e)}')
            return redirect('accounts:profile')
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    return render(request, 'pages/admin/restore_backup.html', {
        'backup': backup
    })
