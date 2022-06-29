from core import matcher, analyser
from core.obj.cpe_record import CPERecord
from core.analyser.category import Category, Rule
from django.http import HttpResponse
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .encoder import VEACHEncoder
from .serializers import *
import json
import csv


@api_view(['GET'])
def cve_db_info(request: Request):
    '''
    Returns info on the CVE db (size, last updated, etc..)
    '''
    return HttpResponse(json.dumps(matcher.get_cve_collection_info()), status=status.HTTP_200_OK)


@api_view(['GET'])
def scan(request: Request):
    '''
    Returns a list of CPE URIs from Scanner module
    '''
    cpe_uris = []
    csv_file = open("core/scanner/fake_scanner.csv")
    reader = csv.reader(csv_file, delimiter=',')
    for row in reader:
        cpe_uris.append(row[0].lower())
    return HttpResponse(json.dumps(cpe_uris), status=status.HTTP_200_OK)
    # return HttpResponse(json.dumps(list(matcher.matches[request.data]), cls=VEACHEncoder, indent=4), status=status.HTTP_200_OK)
    # cpe_record = CPERecordSerializer(data=request.data)
    # if cpe_record.is_valid():
    #     cpe_record.save()
    #     return Response(cpe_record.data)
    # nodes = NodeModel.objects.all()
    # serializer = NodeSerializer(nodes, many=True)


@api_view(['GET'])
def match(request: Request):
    '''
    Get a list of CPE URIs, match them to CVE, analyse the CVE and returns a list of Categories (if exists)
    '''
    for uri in request.data:
        if not CPERecord.is_valid(uri):
            return HttpResponse({"Error": f"{uri} is not a valid CPE URI"}, status=status.HTTP_400_BAD_REQUEST)

    for uri in request.data:
        matcher.match(cpe_uri=uri)
        if matcher.matches[uri]:
            analyser.add(matcher.matches[uri])

    analyser.analyse()
    return HttpResponse({json.dumps(analyser.cve_categories, cls=VEACHEncoder, indent=4)}, status=status.HTTP_200_OK)
