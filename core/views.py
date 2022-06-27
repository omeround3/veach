from core import matcher
from django.http import HttpResponse
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .encoder import VEACHEncoder
from .serializers import *
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
