from core import views
from django.urls import path, include
from rest_framework import routers

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('cpe', views.cpe, name='cpe'),
    path('sync-db', views.sync_db, name='sync_db'),
]