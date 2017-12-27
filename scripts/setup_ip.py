from jinja2 import Template
from django.conf import settings
import sys


def run(*args):
    print("Server IP :")
    ip = input('ip : ')

    with open(settings.BASE_DIR + "/ossec/ossec-conf-client.xml") as f:
        CONF_FULL_DEFAULT = f.read()
    t = Template(CONF_FULL_DEFAULT)
    final_conf_default = t.render(ip=ip)
    with open(settings.BASE_DIR + "/ossec/ossec-conf-client.xml", 'w') as f:
        f.write(final_conf_default)

    with open(settings.BASE_DIR + "/ossec/preloaded-vars.conf") as f:
        CONF_INSTALL = f.read()
    t = Template(CONF_INSTALL)
    final_conf_install = t.render(ip=ip)
    with open(settings.BASE_DIR + "/ossec/preloaded-vars.conf", 'w') as f:
        f.write(final_conf_install)

    sys.exit(0)
