import logging

from django.contrib import admin, messages
from core.models import Server, SshKey, OsSupported
from django_celery_beat.models import CrontabSchedule
from.forms import ConfOssecServerSetForm
from ossec.models import OssecAgent, OssecServer, RuleOssec, RuleSetOssec, DecoderOssec, ConfOssecAgent, \
    ConfOssecServer, RuleUtility

logger = logging.getLogger(__name__)


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
        obj.name = "Ossec-Server"
        obj.save()
        response = obj.test()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test configuration OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configuration failed ! " + str(response['errors']))
        sshkey = SshKey(name="Ossec-Server")
        sshkey.save()
        server = Server(name="main-server-localhost",
                        host="127.0.0.1",
                        os=OsSupported.get_by_id(1),
                        ssh_private_key_file=sshkey
                        )
        server.save()
        ossec_server = OssecServer(name="main-server", configuration=obj, secure_deployment=True,
                                   installed=True,
                                   scheduled_check_enabled=True,
                                   scheduled_check_crontab=CrontabSchedule.objects.get(id=2),
                                   server=server)
        ossec_server.save()
        messages.add_message(request, messages.SUCCESS, "Server Ossec added successfully !")


class RuleUtilityAdmin(admin.ModelAdmin):
    list_display = ('__str__',)
    list_display_links = None

    class Media:
        js = (
            'ossec/js/mask-log_format.js',
        )

    def save_model(self, request, obj, form, change):
        obj.create()
        super().save_model(request, obj, form, change)

    def get_actions(self, request):
        actions = super(RuleUtilityAdmin, self).get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions


admin.site.register(ConfOssecServer, ConfOssecServerAdmin)
admin.site.register(OssecAgent)
admin.site.register(RuleSetOssec)
admin.site.register(RuleOssec)
admin.site.register(DecoderOssec)
admin.site.register(ConfOssecAgent)
admin.site.register(RuleUtility, RuleUtilityAdmin)
