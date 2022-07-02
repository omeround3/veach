from core import views
from django.urls import path, include
from rest_framework import routers

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('start_scan', views.start_scan, name='start_scan'),
    path('cve_db_info', views.cve_db_info, name='cve_db_info'),
    path('sync-db', views.sync_db, name='sync_db'),
    path('cve_categories', views.cve_categories, name='cve_categories'),
    path('num_of_components', views.num_of_components, name='num_of_components'),
    path('mitigate', views.mitigate, name='mitigate'),
    path('is_scanning', views.is_scanning, name='is_scanning'),
    # path('test_run', views.test_run, name='test_run'),
    # path('test_get', views.test_get, name='test_get'),
]
