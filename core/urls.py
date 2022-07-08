from core import views
from django.urls import path, include
from rest_framework import routers
from rest_framework.authtoken import views as drf_views

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('start_scan', views.start_scan, name='start_scan'),
    path('get_status', views.get_status, name='get_status'),
    path('stop_scan', views.stop_scan, name='stop_scan'),
    path('cve_db_info', views.cve_db_info, name='cve_db_info'),
    path('sync-db', views.sync_db, name='sync_db'),
    path('cve_categories', views.cve_categories, name='cve_categories'),
    path('num_of_components', views.num_of_components, name='num_of_components'),
    path('mitigate', views.mitigate, name='mitigate'),
    path('scan-settings', views.scan_settings, name='scan_settings'),
    path('login/', views.Login.as_view()),
    path('api-token-auth/', drf_views.obtain_auth_token)
]
