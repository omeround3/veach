from core import matcher
from core.encoder import VEACHEncoder
from core.serializers import UserSerializer, GroupSerializer
from django.contrib.auth.models import User, Group
from django.http import HttpResponse
from rest_framework import status, viewsets, permissions
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import api_view
import json


@api_view(['POST'])
def cpe(request: Request):
    print(request.data)
    matcher.match(request.data)
    return HttpResponse(json.dumps(list(matcher.matches[request.data]), cls=VEACHEncoder, indent=4), status=status.HTTP_200_OK)
    # cpe_record = CPERecordSerializer(data=request.data)
    # if cpe_record.is_valid():
    #     cpe_record.save()
    #     return Response(cpe_record.data)
    # nodes = NodeModel.objects.all()
    # serializer = NodeSerializer(nodes, many=True)
    
def sync_db():
    pass

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