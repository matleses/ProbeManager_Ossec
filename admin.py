import logging
import subprocess
from django.contrib import admin, messages
from django.conf import settings
from jinja2 import Template
from core.models import Server, SshKey, OsSupported
from django_celery_beat.models import CrontabSchedule
from.forms import ConfOssecServerSetForm
from ossec.models import OssecAgent, OssecServer, ConfOssec, RuleOssec, RuleSetOssec, DecoderOssec, ConfOssecAgent
from ossec.models import ConfOssecServer, RuleUtility

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
        obj.name = "Ossec-Server"
        obj.save()
        response = obj.test()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test configuration OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configuration failed ! " + str(response['errors']))
        # generate a ssh key
        sshkey = SshKey(name="Ossec-Server-SSH", file="~/.ssh/ossec-server_rsa")
        sshkey.save()
        # port ssh -> grep 'Port ' /etc/ssh/sshd_config | cut -f2  -d ' '
        process = subprocess.Popen('grep "Port " /etc/ssh/sshd_config | cut -f2 -d " "', stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, universal_newlines=True, shell=True)
        outdata, errdata = process.communicate()
        try:
            port = int(outdata)
        except TypeError:
            port = 22
        server = Server(name="main-Ossec-server",
                        host="127.0.0.1",
                        remote_user=settings.OSSEC_REMOTE_USER,
                        remote_port=port,
                        os=OsSupported.objects.get(name=settings.OSSEC_REMOTE_OS),
                        become=True,
                        become_pass="",
                        ssh_private_key_file=sshkey
                        )
        server.save()
        ossec_server = OssecServer(name="Ossec-server", configuration=obj, secure_deployment=True,
                                   installed=True,
                                   scheduled_check_enabled=True,
                                   scheduled_check_crontab=CrontabSchedule.objects.get(id=2),
                                   server=server)
        ossec_server.save()
        ip = obj.external_ip
        with open(settings.BASE_DIR + "/ossec/ossec-conf-agent.xml") as f:
            conf_full_default = f.read()
        t = Template(conf_full_default)
        final_conf_default = t.render(ip=ip)
        with open(settings.BASE_DIR + "/ossec/ossec-conf-agent.xml", 'w') as f:
            f.write(final_conf_default)

        with open(settings.BASE_DIR + "/ossec/preloaded-vars-agent.conf") as f:
            conf_install = f.read()
        t = Template(conf_install)
        final_conf_install = t.render(ip=ip)
        with open(settings.BASE_DIR + "/ossec/preloaded-vars-agent.conf", 'w') as f:
            f.write(final_conf_install)
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
admin.site.register(OssecAgent, OssecAgentAdmin)
admin.site.register(RuleSetOssec)
admin.site.register(RuleOssec)
admin.site.register(ConfOssec)
admin.site.register(DecoderOssec)
admin.site.register(ConfOssecAgent, ConfOssecAgentAdmin)
admin.site.register(RuleUtility, RuleUtilityAdmin)
