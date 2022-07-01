from core import views
from django.urls import path, include
from rest_framework import routers
from rest_framework.authtoken import views as drf_views

router = routers.DefaultRouter()
router.register(r'login', views.Login)
router.register(r'sync-db', views.sync_db)
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('api-token-auth/', drf_views.obtain_auth_token)
]