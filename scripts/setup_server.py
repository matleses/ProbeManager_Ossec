import sys

from django.conf import settings
from django_celery_beat.models import CrontabSchedule
from jinja2 import Template

from home.models import Server, SshKey, OsSupported
from ossec.models import OssecServer, ConfOssecServer


def run(*args):
    ip = input('IP server : ')

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

    # Set IP in settings
    with open(settings.BASE_DIR + "/ossec/settings.py", 'a') as f:
        f.write("OSSEC_SERVER_IP = '" + ip + "'")

    # TODO create server Ossec instance  Becareful install_modules before create db
    configuration = ConfOssecServer(name="main-server-conf")
    configuration.save()
    sshkey = SshKey()

    server = Server(name="main-server-localhost",
                    host="127.0.0.1",
                    os=OsSupported.get_by_id(1),
                    ssh_private_key_file=sshkey
                    )
    server.save()
    ossec_server = OssecServer(name="main-server",
                               description="",
                               secure_deployment=True,
                               scheduled_check_enabled=True,
                               scheduled_check_crontab=CrontabSchedule.objects.get(id=2),
                               server=server,
                               configuration=configuration,
                               )
    ossec_server.save()
    sys.exit(0)
