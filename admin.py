from django.contrib import admin
from ossec.models import Ossec, RuleOssec, RuleSetOssec, DecoderOssec, ConfOssec
import logging


logger = logging.getLogger(__name__)


admin.site.register(Ossec)
admin.site.register(RuleSetOssec)
admin.site.register(RuleOssec)
admin.site.register(DecoderOssec)
admin.site.register(ConfOssec)
