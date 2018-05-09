import logging
from django.contrib import admin, messages
from .forms import ConfOssecServerSetForm
from .models import OssecAgent, OssecServer, ConfOssec, RuleOssec, RuleSetOssec, DecoderOssec, ConfOssecAgent, \
    ConfOssecServer, RuleUtility


logger = logging.getLogger(__name__)


class ConfOssecAgentAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        if len(OssecServer.get_all()) == 0:
            return False
        else:
            return True


class OssecAgentAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        if len(OssecServer.get_all()) == 0:
            return False
        else:
            return True


class ConfOssecServerAdmin(admin.ModelAdmin):
    def get_form(self, request, obj=None, **kwargs):
        """A ModelAdmin that uses a different form class when adding an object."""
        return ConfOssecServerSetForm

    def has_delete_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request):
        if len(OssecServer.get_all()) == 0:
            return True
        else:
            return False

    def get_actions(self, request):
        actions = super().get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        response = ConfOssecServer.objects.get(name="Ossec-Server").test()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test configuration OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configuration failed ! " + str(response['errors']))
        messages.add_message(request, messages.SUCCESS, "Server Ossec added successfully !")


class RuleUtilityAdmin(admin.ModelAdmin):
    list_display = ('__str__',)
    list_display_links = None

    class Media:
        js = (
            'ossec/js/mask-log_format.js',
        )

    def has_delete_permission(self, request, obj=None):
        return False

    def get_actions(self, request):
        actions = super(RuleUtilityAdmin, self).get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions


admin.site.register(ConfOssecServer, ConfOssecServerAdmin)
admin.site.register(OssecAgent, OssecAgentAdmin)
admin.site.register(RuleSetOssec)
admin.site.register(RuleOssec)
admin.site.register(ConfOssec)
admin.site.register(DecoderOssec)
admin.site.register(ConfOssecAgent, ConfOssecAgentAdmin)
admin.site.register(RuleUtility, RuleUtilityAdmin)
