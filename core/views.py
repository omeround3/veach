import threading
from core import orchestrator
from core.db import sync_collections
from core.encoder import VEACHEncoder
from core.obj.cpe_record import CPERecord
from core.serializers import UserSerializer, GroupSerializer
from django.contrib.auth.models import User, Group
from django.http import HttpResponse
from rest_framework import status, viewsets, permissions
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import api_view
import json
import logging
import csv

logger = logging.getLogger("veach")


# @api_view(['GET'])
# def test_run(request: Request):
#     '''
#     Returns info on the CVE db (size, last updated, etc..)
#     '''
#     test.wait()
#     return HttpResponse({"OK": "OK"}, status=status.HTTP_200_OK)


# @api_view(['GET'])
# def test_get(request: Request):
#     '''
#     Returns info on the CVE db (size, last updated, etc..)
#     '''
#     return HttpResponse(json.dumps(test.get_vals()), status=status.HTTP_200_OK)


@api_view(['POST'])
def mitigate(request: Request):
    '''
    Returns info on the CVE db (size, last updated, etc..)
    '''
    # output = {'num': len(orchestrator.invoke_scanner())}
    cpe_uri = request.data
    output = orchestrator.invoke_mitigator(cpe_uri)
    if not output:
        output
    return HttpResponse(json.dumps(output, cls=VEACHEncoder, indent=4), status=status.HTTP_200_OK)


@api_view(['GET'])
def num_of_components(request: Request):
    '''
    Returns info on the CVE db (size, last updated, etc..)
    '''
    # output = {'num': len(orchestrator.invoke_scanner())}
    cpe_uris = []
    csv_file = open("core/scanner/fake_scanner.csv")
    reader = csv.reader(csv_file, delimiter=',')
    for row in reader:
        cpe_uris.append(row[0].lower())
    output = {'num': len(cpe_uris)}

    return HttpResponse(json.dumps(output), status=status.HTTP_200_OK)


@api_view(['GET'])
def cve_db_info(request: Request):
    '''
    Returns info on the CVE db (size, last updated, etc..)
    '''
    return HttpResponse(json.dumps(orchestrator.get_cve_collection_info()), status=status.HTTP_200_OK)


@api_view(['GET'])
def start_scan(request: Request):
    '''
    Starts the scanning process
    '''
    cpe_uris = []
    csv_file = open("core/scanner/fake_scanner.csv")
    reader = csv.reader(csv_file, delimiter=',')
    for row in reader:
        cpe_uris.append(row[0].lower())

    # cpe_uris = orchestrator.invoke_scanner()

    th = threading.Thread(target=orchestrator.invoke_matcher, args=[cpe_uris])
    th.start()
    th.join()
    return HttpResponse(status=status.HTTP_200_OK)


@api_view(['GET'])
def cve_categories(request: Request):
    '''
    Starts the scanning process
    '''
    output = orchestrator.get_cve_categories()
    return HttpResponse(json.dumps(output, cls=VEACHEncoder, indent=4), status=status.HTTP_200_OK)


@api_view(['GET'])
def sync_db(request: Request, format=None):
    content = {
        'sync-status': False
    }

    if sync_collections.dump(["cvedetails", "cpematches"]) \
            and sync_collections.restore(["cvedetails", "cpematches"]):
        content['sync-status'] = True
    return Response(data=content)


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all().order_by('-id')
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]
