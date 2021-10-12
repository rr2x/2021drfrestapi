from django.contrib import admin
from django.urls import path, include

from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title='expense api',
        default_version='v1',
        description='description-test'
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('swagger/',
         schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('api/api.json',
         schema_view.without_ui(cache_timeout=0), name='schema-no-ui'),
    path('redoc/', schema_view.with_ui(
        'redoc', cache_timeout=0), name='schema-redoc'),
    path('admin/', admin.site.urls),
    path('auth/', include('authentication.urls')),
    path('expenses/', include('expenses.urls')),
    path('income/', include('income.urls')),
    path('userstats/', include('userstats.urls')),
    path('social_auth/', include(('social_auth.urls', 'social_auth'),
                                 namespace="social_auth")),
]
