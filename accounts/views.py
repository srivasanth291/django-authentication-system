from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, login,logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import never_cache
from django.contrib.auth.models import User

@never_cache
def signup_view(request):
    if request.user.is_authenticated:
        return redirect('accounts:dashboard')
    
    if request.method == 'POST':
        username=request.POST.get('username')
        password=request.POST.get('password')
        confirm_password=request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request,'passwords do not match')
            return redirect('accounts:signup')
        
        if User.objects.filter(username=username).exists():
            messages.error(request,'username already taken')
            return redirect('accounts:signup')
        

        User.objects.create_user(username=username,password=password)   
        messages.success(request, 'Account created successfully.')
        return redirect('accounts:login')
    return render(request,'accounts/signup.html')

@never_cache
def login_view(request):
    if request.user.is_authenticated:
        return redirect('accounts:dashboard')
    if request.method =='POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(
            request,
            username=username,
            password=password
        )
        if user is not None:
            login(request, user)
            return redirect('accounts:dashboard')  # Redirect to a dashboard or home page after login
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'accounts/login.html')

@login_required
def dashboard(request):
    return render(request, 'accounts/dashboard.html')

@never_cache
def logout_view(request):
    logout(request)
    return redirect('accounts:login')