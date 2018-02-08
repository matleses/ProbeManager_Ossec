import logging

from django.contrib import admin

from ossec.models import OssecAgent, RuleOssec, RuleSetOssec, DecoderOssec, ConfOssecAgent, ConfOssecServer, RuleUtility

logger = logging.getLogger(__name__)


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


admin.site.register(OssecAgent)
admin.site.register(RuleSetOssec)
admin.site.register(RuleOssec)
admin.site.register(DecoderOssec)
admin.site.register(ConfOssecAgent)
admin.site.register(ConfOssecServer)
admin.site.register(RuleUtility, RuleUtilityAdmin)
