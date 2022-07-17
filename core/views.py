from core import orchestrator
from core.authenticator.authenticator import Authenticator
from core.db.sync_db import SyncDb
from core.encoder import VEACHEncoder
from core.orchestrator.orchestrator import Orchetrator
from core.serializers import UserSerializer, GroupSerializer, AuthTokenSerializer
from core.utils import get_settings_value, set_settings_value
from django.contrib.auth.models import User, Group
from django.http import HttpResponse, HttpResponseServerError
from rest_framework import status, viewsets, authentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication, BasicAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authtoken.views import ObtainAuthToken
import threading
import json
import logging

logger = logging.getLogger("veach")
th = None  # thread needs to be global so we can stop the scan if we want
is_scanned = False


@api_view(['GET', 'POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def rules_settings(request: Request):
    """
    GET: gets rules settings
    POST: updates rules settings
    """
    content = {}
    if request.method == 'GET':
        content['attack_vector'] = get_settings_value(
            "RULES", "attack_vector").split(",")
        content['attack_complexity'] = get_settings_value(
            "RULES", "attack_complexity")
        content['confidentiality_impact'] = get_settings_value(
            "RULES", "confidentiality_impact")
        content['integrity_impact'] = get_settings_value(
            "RULES", "integrity_impact")
        content['availability_impact'] = get_settings_value(
            "RULES", "availability_impact")
        return Response(data=content, status=status.HTTP_200_OK)
    elif request.method == 'POST':
        attack_vector = request.data['attack_vector']
        attack_complexity = request.data['attack_complexity']
        confidentiality_impact = request.data['confidentiality_impact']
        integrity_impact = request.data['integrity_impact']
        availability_impact = request.data['availability_impact']

        res1 = set_settings_value(
            "RULES", "attack_vector", ",".join(attack_vector))
        res2 = set_settings_value(
            "RULES", "attack_complexity", attack_complexity)
        res3 = set_settings_value(
            "RULES", "confidentiality_impact", confidentiality_impact)
        res4 = set_settings_value(
            "RULES", "integrity_impact", integrity_impact)
        res5 = set_settings_value(
            "RULES", "availability_impact", availability_impact)

        if res1 and res2 and res3 and res4 and res5:
            content['updated_attack_vector'] = res1
            content['updated_attack_complexity'] = res2
            content['updated_confidentiality_impact'] = res3
            content['updated_integrity_impact'] = res4
            content['updated_availability_impact'] = res5
            content['response'] = "Updated config file successfully"
            return Response(data=content, status=status.HTTP_200_OK)
        else:
            return Response(data="Couldn't update config file", status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def scan_settings(request: Request):
    """
    GET: gets scan settings
    POST: updates scan settings
    """
    content = {}
    if request.method == 'GET':
        content['is_scan_software'] = get_settings_value("SCANNER", "software")
        content['is_scan_hardware'] = get_settings_value("SCANNER", "hardware")
        return Response(data=content, status=status.HTTP_200_OK)
    elif request.method == 'POST':
        is_scan_software = request.data['is_scan_software']
        is_scan_hardware = request.data['is_scan_hardware']

        res1 = set_settings_value("SCANNER", "software", is_scan_software)
        res2 = set_settings_value("SCANNER", "hardware", is_scan_hardware)

        if res1 and res2:
            content['updated_scan_software'] = res1
            content['updated_scan_hardware'] = res2
            content['response'] = "Updated config file successfully"
            return Response(data=content, status=status.HTTP_200_OK)
        else:
            return Response(data="Couldn't update config file", status=status.HTTP_400_BAD_REQUEST)


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
    if output:
        for key, val in output.items():
            if not val:
                output[key] = None
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


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def start_scan(request: Request):
    '''
    Starts the scanning process
    '''
    username = request.data['username']
    password = request.data['password']

    global orchestrator
    orchestrator = Orchetrator()
    orchestrator.set_credentials(username, password)
    orchestrator.is_scanning = True
    orchestrator.is_stopped = False
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

    sync_db = SyncDb.instance()
    return HttpResponse(json.dumps({"status": output, 'db_status': sync_db.state}), status=status.HTTP_200_OK)


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
@authentication_classes([BasicAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def sync_db(request: Request, format=None):
    """
    API get endpoint to trigger local database synchronization
    """
    sync_db = SyncDb.instance()
    sync_db.update_db()
    content = {
        'is_syncing': SyncDb.is_syncing,
        'state': sync_db.state,
        'is_synced': SyncDb.is_synced
    }
    return Response(data=content, status=status.HTTP_200_OK)


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
