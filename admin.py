from django.contrib import admin
from ossec.models import Ossec, RuleOssec, RuleSetOssec, DecoderOssec, ConfOssecAgent, ConfOssecServer, Util
import logging


logger = logging.getLogger(__name__)


class UtilAdmin(admin.ModelAdmin):

    def save_model(self, request, obj, form, change):
        obj.util()
        super().save_model(request, obj, form, change)


admin.site.register(Ossec)
admin.site.register(RuleSetOssec)
admin.site.register(RuleOssec)
admin.site.register(DecoderOssec)
admin.site.register(ConfOssecAgent)
admin.site.register(ConfOssecServer)
admin.site.register(Util, UtilAdmin)
