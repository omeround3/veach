import threading
from core import orchestrator
from core.db import sync_collections
from core.authenticator.authenticator import Authenticator
from core.encoder import VEACHEncoder
from core.orchestrator.orchestrator import Orchetrator
from core.serializers import UserSerializer, GroupSerializer, AuthTokenSerializer
from django.contrib.auth.models import User, Group
from django.http import HttpResponse, HttpResponseServerError
from rest_framework import status, viewsets, permissions, authentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authtoken.views import ObtainAuthToken
import json
import logging
import csv

logger = logging.getLogger("veach")
th = None  # thread needs to be global so we can stop the scan if we want
is_scanned = False


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
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
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def num_of_components(request: Request):
    '''
    Returns info on the CVE db (size, last updated, etc..)
    '''
    output = {'num': len(orchestrator.software_list) +
              len(orchestrator.hardware_list)}
    # cpe_uris = []
    # csv_file = open("core/scanner/fake_scanner.csv")
    # reader = csv.reader(csv_file, delimiter=',')
    # for row in reader:
    #     cpe_uris.append(row[0].lower())
    # output = {'num': len(cpe_uris)}

    return HttpResponse(json.dumps(output), status=status.HTTP_200_OK)


class Login(ObtainAuthToken):
    """
    Authenticates a sudo user and returns authorization token
    based on existing django superuser

    * Requires sudo username and password.
    """
    serializer_class = AuthTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        logger.debug(f'[LOGIN] User {username} and password {password}')
        authenticator = Authenticator(username, password)
        if authenticator.authenticated:
            logger.info(f'[LOGIN] User authenticated successfully')
            try:
                user = User.objects.get(username="veach")
            except User.DoesNotExist as err:
                logger.error(
                    f"[LOGIN] User 'veach' doesn't exists \n {err}", exc_info=True)
            if user:
                try:
                    token = Token.objects.get(user=user)
                    content = {
                        'token': token.key
                    }
                except Token.DoesNotExist as err:
                    logger.error(
                        f"[LOGIN] Token for user 'veach' doesn't exists \n {err}", exc_info=True)
        else:
            logger.info(f'[LOGIN] User was not authenticated')
            content = {
                'token': 'null'
            }
        return Response(content)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def cve_db_info(request: Request):
    '''
    Returns info on the CVE db (size, last updated, etc..)
    '''
    return HttpResponse(json.dumps(orchestrator.get_cve_collection_info()), status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def start_scan(request: Request):
    '''
    Starts the scanning process
    '''
    global is_scanned
    if is_scanned:
        global orchestrator
        orchestrator = Orchetrator()
    is_scanned = True
    orchestrator.is_scanning = True
    orchestrator.is_stopped = False
    # cpe_uris = []
    # csv_file = open("core/scanner/fake_scanner.csv")
    # reader = csv.reader(csv_file, delimiter=',')
    # for row in reader:
    #     cpe_uris.append(row[0].lower())

    cpe_uris = orchestrator.invoke_scanner()
    global th
    th = threading.Thread(target=orchestrator.invoke_matcher, args=[cpe_uris])
    th.start()
    th.join()
    orchestrator.is_matched = True
    orchestrator.is_scanning = False
    return HttpResponse(status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def get_status(request: Request):
    '''
    Gets the scanning status
    '''
    output = None
    global orchestrator
    if not orchestrator.is_stopped and orchestrator.is_scanning:
        output = "scanning"
    elif orchestrator.is_stopped and not orchestrator.is_scanning:
        output = "stopped"
    elif orchestrator.is_matched:
        output = "finished"
    else:
        output = "new"

    return HttpResponse(json.dumps({"status": output}), status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def stop_scan(request: Request):
    '''
    Stops the scanning process
    '''
    global orchestrator
    orchestrator.is_stopped = True

    while (orchestrator.is_stopped):
        pass

    global th
    if th.is_alive():
        return HttpResponseServerError()
    else:
        return HttpResponse(status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def cve_categories(request: Request):
    '''
    Starts the scanning process
    '''
    output = orchestrator.get_cve_categories()
    return HttpResponse(json.dumps(output, cls=VEACHEncoder, indent=4), status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
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

    authentication_classes = [authentication.TokenAuthentication]
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """

    authentication_classes = [authentication.TokenAuthentication]
    queryset = Group.objects.all().order_by('-id')
    serializer_class = GroupSerializer
    permission_classes = [IsAuthenticated]
