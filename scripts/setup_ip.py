from jinja2 import Template
from django.conf import settings
import sys


def run(*args):
    print("Server IP :")
    ip = input('ip : ')

    with open(settings.BASE_DIR + "/ossec/ossec-conf-agent.xml") as f:
        CONF_FULL_DEFAULT = f.read()
    t = Template(CONF_FULL_DEFAULT)
    final_conf_default = t.render(ip=ip)
    with open(settings.BASE_DIR + "/ossec/ossec-conf-agent.xml", 'w') as f:
        f.write(final_conf_default)

    with open(settings.BASE_DIR + "/ossec/preloaded-vars-agent.conf") as f:
        CONF_INSTALL = f.read()
    t = Template(CONF_INSTALL)
    final_conf_install = t.render(ip=ip)
    with open(settings.BASE_DIR + "/ossec/preloaded-vars-agent.conf", 'w') as f:
        f.write(final_conf_install)

    # Set IP in settings
    with open(settings.BASE_DIR + "/ossec/settings.py", 'a') as f:
        f.write("OSSEC_SERVER_IP = '" + ip + "'")

    sys.exit(0)
