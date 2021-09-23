from django.conf.urls import include, url
from django.contrib import admin

app_name='testprofiles'

urlpatterns = [
    url(r'^saml2/', include('djangosaml2.urls')),
    url(r'^admin/', admin.site.urls),
]
