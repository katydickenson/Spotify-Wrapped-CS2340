from django.shortcuts import render

# Create your views here.
from django.shortcuts import render

def home(request):
    return render(request, 'wrapped/home.html')

def wrapdata(request):
    return render(request, 'wrapped/wrapdata.html')