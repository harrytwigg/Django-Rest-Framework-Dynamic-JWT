from django.contrib import admin
from .models import AuthenticationSettingsModel

class AuthenticationSettingsAdmin(admin.ModelAdmin):
    pass


admin.site.register(AuthenticationSettingsModel, AuthenticationSettingsAdmin)