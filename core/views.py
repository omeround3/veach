from core import matcher
from core.authenticator import authenticator
from core.db import sync_collections
from core.authenticator.authenticator import Authenticator
from core.encoder import VEACHEncoder
from core.serializers import UserSerializer, GroupSerializer, AuthTokenSerializer
from django.contrib.auth.models import User, Group
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status, viewsets, permissions
from rest_framework.authtoken.models import Token
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.authtoken.views import ObtainAuthToken
import json
import logging

logger = logging.getLogger("veach")


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
                logger.error(f"[LOGIN] User 'veach' doesn't exists \n {err}", exc_info=True)
            if user:
                try:
                    token = Token.objects.get(user=user)
                    content = {
                        'token': token.key
                    }
                except Token.DoesNotExist as err:
                    logger.error(f"[LOGIN] Token for user 'veach' doesn't exists \n {err}", exc_info=True)
        else:
            logger.info(f'[LOGIN] User was not authenticated')
            content = {
                'token': 'null'
            }
        return Response(content)


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
