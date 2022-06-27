# from uuid import uuid4
# from django.db import models
# # Create your models here


# class CPERecordModel(models.Model):
#     _id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
#     _generated_id = models.TextField()
#     _cpe_version = models.TextField()
#     _part = models.TextField()
#     _vendor = models.TextField()
#     _product = models.TextField()
#     _version = models.TextField()
#     _update = models.TextField()
#     _edition = models.TextField()
#     _language = models.TextField()
#     _sw_edition = models.TextField()
#     _target_sw = models.TextField()
#     _target_hw = models.TextField()
#     _other = models.TextField()
#     _version_end_excluding = models.TextField()
#     _version_start_excluding = models.TextField()
#     _version_end_including = models.TextField()
#     _version_start_including = models.TextField()


# class NodeModel(models.Model):
#     _id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
#     operator = models.TextField()
#     cpe_match = models.ManyToManyField(CPERecordModel)


# class CVERecordModel(models.Model):
#     _id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
#     id = models.TextField()
#     _base_metric_v2 = models.JSONField()
#     _base_metric_v3 = models.JSONField()
#     _published_date = models.DateField()
#     _lastModified_date = models.DateField()
#     _nodes = models.ManyToManyField(NodeModel)


# class CVSSRecordV3Model(models.Model):
#     _id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
#     vector_string_attributes = models.JSONField()
#     vector_string = models.TextField()


# class RuleModel(models.Model):
#     _id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
#     record_scheme = models.ForeignKey(
#         CVSSRecordV3Model, on_delete=models.CASCADE)
#     severity = models.FloatField()
#     is_critical = models.BooleanField()


# class CategoryModel(models.Model):
#     _id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
#     record_scheme = models.ForeignKey(
#         CVSSRecordV3Model, on_delete=models.CASCADE)

#     rules = models.ManyToManyField(RuleModel)
#     affected_records = models.ManyToManyField(CVERecordModel)

#     average = models.FloatField()
#     tag = models.TextField()
#     severity = models.FloatField()
#     is_critical = models.BooleanField()
