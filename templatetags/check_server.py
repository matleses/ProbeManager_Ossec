import logging
from django import template
from ossec.models import OssecServer

logger = logging.getLogger(__name__)
register = template.Library()


@register.filter
def check_server(instance):
    if len(OssecServer.get_all()) > 0:
        return True
    else:
        return False
