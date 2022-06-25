from django.shortcuts import render
from django.http import HttpResponse
from .db import sync_db

# Create your views here.


def index(request):
    sync_db.dump(["cvedetails", "cpematches"], "/root/veach")    
    return HttpResponse("VEACH Project")