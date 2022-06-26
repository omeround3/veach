from django.shortcuts import render
from django.http import HttpResponse
from .utils import timeit

# Create your views here.

@timeit
def index(request):
    return HttpResponse("VEACH Project")