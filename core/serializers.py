# from attr import fields
# from django.urls import path, include
from django.contrib.auth.models import User, Group
from rest_framework import serializers
# from .models import NodeModel, CPERecordModel

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'is_staff']

class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['url', 'name']
        
# class CVSSRecordV3Serializer(serializers.ModelSerializer):
#     class Meta:
#         model = CPERecordModel
#         fields = '__all__'


# class RuleSerializer(serializers.ModelSerializer):
#     record_scheme = CVSSRecordV3Serializer(many=False, read_only=True)

#     class Meta:
#         model = CPERecordModel
#         fields = '__all__'


# class CPERecordSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = CPERecordModel
#         fields = '__all__'


# class NodeSerializer(serializers.ModelSerializer):
#     cpe_match = CPERecordSerializer(many=True, read_only=True)

#     class Meta:
#         model = NodeModel
#         fields = '__all__'


# class CVERecordSerializer(serializers.ModelSerializer):

#     nodes = NodeSerializer(many=True, read_only=True)

#     class Meta:
#         model = CPERecordModel
#         fields = '__all__'


# class CategorySerializer(serializers.ModelSerializer):
#     record_scheme = CVSSRecordV3Serializer(many=False, read_only=True)
#     rules = RuleSerializer(many=True, read_only=True)
#     affected_records = CVERecordSerializer(many=True, read_only=True)

#     class Meta:
#         model = CPERecordModel
#         fields = '__all__'
