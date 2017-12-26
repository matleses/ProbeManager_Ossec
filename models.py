from django.db import models
from home.ssh import execute, execute_copy
from home.models import Probe, ProbeConfiguration
from rules.models import RuleSet, Rule
import logging
import os
import select2.fields
from django.conf import settings
from django.utils import timezone
from django.db.models import Q


logger = logging.getLogger('ossec')


class ConfOssec(ProbeConfiguration):
    with open(settings.BASE_DIR + "/ossec/default-Ossec-conf.xml") as f:
        CONF_FULL_DEFAULT = f.read()
    with open(settings.BASE_DIR + "/ossec/preloaded-vars.conf") as f:
        CONF_INSTALL = f.read()
    conf_binary_dir = models.CharField(max_length=400, default="/var/ossec/bin")
    conf_install_text = models.TextField(default=CONF_INSTALL)
    conf_install_file = models.CharField(max_length=400, default="/var/ossec/etc/preloaded-vars.conf")
    conf_rules_file = models.CharField(max_length=400, default="/var/ossec/etc/local_rules.xml")
    conf_decoders_file = models.CharField(max_length=400, default='/var/ossec/etc/local_decoder.xml')
    conf_file = models.CharField(max_length=400, default="/var/ossec/etc/ossec.conf")
    conf_file_text = models.TextField(default=CONF_FULL_DEFAULT)

    def __str__(self):
        return self.name

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object


class RuleOssec(Rule):
    def __str__(self):
        return self.name + "  " + self.description

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    def test(self):
        if self.server.os.name == 'debian':
            command = self.configuration.conf_binary_dir + "/ossec-logtest"
        else:
            raise Exception("Not yet implemented")
        tasks = {"test": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return True


class DecoderOssec(Rule):
    def __str__(self):
        return self.name + "  " + self.description

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object


class RuleSetOssec(RuleSet):
    """
    Set of rules and decoders Ossec compatible
    """
    rules = select2.fields.ManyToManyField(RuleOssec,
                                           blank=True,
                                           ajax=True,
                                           search_field=lambda q: Q(sid__icontains=q) | Q(msg__icontains=q),
                                           sort_field='sid',
                                           js_options={'quiet_millis': 200}
                                           )
    decoders = select2.fields.ManyToManyField(DecoderOssec,
                                              blank=True,
                                              ajax=True,
                                              search_field=lambda q: Q(sid__icontains=q) | Q(name__icontains=q),
                                              sort_field='sid',
                                              js_options={'quiet_millis': 200}
                                              )

    def __str__(self):
        return self.name

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object


class Ossec(Probe):
    """
    Stores an instance of Ossec IDS software.
    """
    rulesets = models.ManyToManyField(RuleSetOssec, blank=True)
    configuration = models.ForeignKey(ConfOssec)
    agent = models.BooleanField(default=False)

    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def __str__(self):
        return self.name + "  " + self.description

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    def test(self):
        if self.server.os.name == 'debian':
            command1 = self.configuration.conf_binary_dir + "/ossec-monitord -t"
            command2 = self.configuration.conf_binary_dir + "/ossec-remoted -t"
            command3 = self.configuration.conf_binary_dir + "/ossec-agentd -t"

        else:
            raise Exception("Not yet implemented")
        if not self.agent:
            tasks = {"test monitord": command1, "test remoted": command2}
        else:
            tasks = {"test monitord": command1, "test agentd": command3}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return True

    def list_agents(self):
        if self.server.os.name == 'debian':
            command = self.configuration.conf_binary_dir + "/list_agents -a"
        else:
            raise Exception("Not yet implemented")
        if not self.agent:
            tasks = {"list agents": command}
        else:
            raise Exception("Not possible for an agent")
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return response

    def install(self):
        tmpdir = settings.BASE_DIR + "/tmp/" + self.name + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        f = open(tmpdir + "temp.install", 'w')
        f.write(self.configuration.conf_install)
        f.close()
        if self.server.os.name == 'debian':
            command1 = 'wget -q -O - https://www.atomicorp.com/RPM-GPG-KEY.atomicorp.txt  | sudo apt-key add -'
            command2 = 'echo "deb https://updates.atomicorp.com/channels/atomic/debian stretch main" >>  /etc/apt/sources.list.d/atomic.list'
            command3 = "apt update"
            command4 = "apt install ossec-hids-server"
            command5 = "apt install ossec-hids-agent"
            command6 = "apt install lynx"
        else:
            raise Exception("Not yet implemented")
        if not self.agent:
            tasks = {"add_key": command1, "add_repo": command2, "update_repo": command3, "install": command4, "install-lynx": command6}
        else:
            tasks = {"add_key": command1, "add_repo": command2, "update_repo": command3, "install": command5}
        try:
            response_install_conf = execute_copy(self.server,
                                                 src=tmpdir + "temp.install",
                                                 dest=self.configuration.conf_install_file,
                                                 become=True
                                                 )
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e)
            return False
        logger.debug("output : " + str(response) + " - " + str(response_install_conf))
        return True

    def update(self):
        if self.server.os.name == 'debian':
            command3 = "apt update"
            command4 = "apt install ossec-hids-server"
            command5 = "apt install ossec-hids-agent"
        else:
            raise Exception("Not yet implemented")
        if not self.agent:
            tasks = {"update_repo": command3, "install": command4}
        else:
            tasks = {"update_repo": command3, "install": command5}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e)
            return False
        logger.debug("output : " + str(response))
        return True

    def restart(self):
        if self.server.os.name == 'debian':
            command = self.configuration.conf_binary_dir + "/ossec-control restart"
        else:
            raise Exception("Not yet implemented")
        tasks = {"restart": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return True

    def start(self):
        if self.server.os.name == 'debian':
            command = self.configuration.conf_binary_dir + "/ossec-control start"
        else:
            raise Exception("Not yet implemented")
        tasks = {"start": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return True

    def stop(self):
        if self.server.os.name == 'debian':
            command = self.configuration.conf_binary_dir + "/ossec-control stop"
        else:
            raise Exception("Not yet implemented")
        tasks = {"stop": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return True

    def reload(self):
        if self.server.os.name == 'debian':
            command = self.configuration.conf_binary_dir + "/ossec-control reload"
        else:
            raise Exception("Not yet implemented")
        tasks = {"reload": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return True

    def status(self):
        if self.server.os.name == 'debian':
            command = self.configuration.conf_binary_dir + "/ossec-control status"
        else:
            raise Exception("Not yet implemented")
        tasks = {"status": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error('Failed to get status : ' + e.__str__())
            return 'Failed to get status : ' + e.__str__()
        logger.debug("output : " + str(response))
        return response['status']

    def deploy_rules(self):
        deploy = True
        tmpdir = settings.BASE_DIR + "/tmp/" + self.name + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        # Rules
        value = ""
        for ruleset in self.rulesets.all():
            for rule in ruleset.rules.all():
                if rule.enabled:
                    value += rule.rule_full + os.linesep
        f = open(tmpdir + "temp.rules", 'w')
        f.write(value)
        f.close()
        # Decoders
        value = ""
        for ruleset in self.rulesets.all():
            for decoder in ruleset.decoders.all():
                if decoder.enabled:
                    value += decoder.rule_full + os.linesep
        f = open(tmpdir + "temp.decoders", 'w')
        f.write(value)
        f.close()
        # write files
        try:
            response_rules = execute_copy(self.server,
                                          src=tmpdir + 'temp.rules',
                                          dest=self.configuration.conf_rules_file,
                                          become=True
                                          )
            response_decoders = execute_copy(self.server,
                                             src=tmpdir + 'temp.decoders',
                                             dest=self.configuration.conf_decoders_file,
                                             become=True
                                             )
            logger.debug("output : " + str(response_rules) + " - " + str(response_decoders))
        except Exception as e:
            logger.error(e)
            deploy = False
        # clean
        if os.path.isfile(tmpdir + 'temp.rules'):
            os.remove(tmpdir + "temp.rules")
        if os.path.isfile(tmpdir + 'temp.decoders'):
            os.remove(tmpdir + "temp.decoders")
        if deploy:
            self.rules_updated_date = timezone.now()
            self.save()
        return deploy

    def deploy_conf(self):
        tmpdir = settings.BASE_DIR + "/tmp/" + self.name + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        value = self.configuration.conf_file_text
        f = open(tmpdir + "temp.conf", 'w')
        f.write(value)
        f.close()
        deploy = True
        try:
            response = execute_copy(self.server,
                                    src=os.path.abspath(tmpdir + 'temp.conf'),
                                    dest=self.configuration.conf_file,
                                    become=True
                                    )
            logger.debug("output : " + str(response))
        except Exception as e:
            logger.error(e)
            deploy = False
        if os.path.isfile(tmpdir + 'temp.conf'):
            os.remove(tmpdir + "temp.conf")
        return deploy


class Util(models.Model):
    """
    Execute a command from util.sh of Ossec IDS software.
    """
    TYPE_ARGUMENTS = (
        ("addfile", "addfile"),
        ("addsite", "addsite"),
        ("adddns", "adddns"),
    )
    ossec = models.ForeignKey(Ossec)
    argument = models.CharField(max_length=255, choices=TYPE_ARGUMENTS)
    option = models.CharField(max_length=400)

    def __str__(self):
        return self.ossec.name + "  " + self.argument + " : " + self.option

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    def util(self):
        arguments = ["addfile", "addsite", "adddns"]
        if self.argument in arguments:
            if self.ossec.server.os.name == 'debian':
                command = self.ossec.server.configuration.conf_binary_dir + "/util.sh " + self.argument + " " + self.option
            else:
                raise Exception("Not yet implemented")
        else:
            raise Exception("Not yet implemented")
        if not self.ossec.agent:
            tasks = {"util": command}
        else:
            raise Exception("Not yet implemented")
        try:
            response = execute(self.ossec.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return True
