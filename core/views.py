from django.shortcuts import render
from django.http import HttpResponse
from .db import sync_cpe

# Create your views here.


def index(request):
    sync_cpe.dump(["cvedetails"], "/root/veach")    
    return HttpResponse("VEACH Project")