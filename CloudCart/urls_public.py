from django.contrib import admin
from django.urls import path, include, re_path

urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(
        r'^(?P<version>(v1))/auth/',
        include('UserAuth.urls'),
    ),
    re_path(
        r'^(?P<version>(v1))/users/',
        include('Users.urls'),
    ),
]
