from core import views
from django.urls import path, include
from rest_framework import routers
from rest_framework.authtoken import views as drf_views

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('login', views.Login.as_view),
    path('sync-db', views.sync_db),
    path('api-token-auth/', drf_views.obtain_auth_token)
]