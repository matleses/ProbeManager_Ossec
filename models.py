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
from jinja2 import Template


logger = logging.getLogger('ossec')


class ConfOssecAgent(ProbeConfiguration):
    with open(settings.BASE_DIR + "/ossec/ossec-conf-agent.xml") as f:
        CONF_FULL_DEFAULT = f.read()
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


class ConfOssecServer(ProbeConfiguration):
    with open(settings.BASE_DIR + "/ossec/ossec-conf-server.xml") as f:
        CONF_FULL_DEFAULT = f.read()
    conf_install_file = models.CharField(max_length=400, default="/var/ossec/etc/preloaded-vars-server.conf")
    conf_rules_file = models.CharField(max_length=400, default="/var/ossec/rules/local_rules.xml")
    conf_decoders_file = models.CharField(max_length=400, default='/var/ossec/etc/local_decoder.xml')
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
        return self.id

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


class DecoderOssec(Rule):
    def __str__(self):
        return self.id

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
                                           search_field=lambda q: Q(id__icontains=q) | Q(rule_full__icontains=q),
                                           sort_field='sid',
                                           js_options={'quiet_millis': 200}
                                           )
    decoders = select2.fields.ManyToManyField(DecoderOssec,
                                              blank=True,
                                              ajax=True,
                                              search_field=lambda q: Q(id__icontains=q) | Q(rule_full__icontains=q),
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
    Stores an instance of Ossec agent IDS software.
    """
    configuration = models.ForeignKey(ConfOssecServer)

    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        self.type = 'Ossec'
        self.subtype = self.__class__.__name__

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

    def restart(self):
        if self.server.os.name == 'debian':
            command = settings.OSSEC_BINARY + "/ossec-control restart"
        else:
            raise Exception("Not yet implemented")
        tasks = {"restart": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return {'status': False, 'errors': e.__str__()}
        logger.debug("output : " + str(response))
        return {'status': True}

    def start(self):
        if self.server.os.name == 'debian':
            command = settings.OSSEC_BINARY + "/ossec-control start"
        else:
            raise Exception("Not yet implemented")
        tasks = {"start": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return {'status': False, 'errors': e.__str__()}
        logger.debug("output : " + str(response))
        return {'status': True}

    def stop(self):
        if self.server.os.name == 'debian':
            command = settings.OSSEC_BINARY + "/ossec-control stop"
        else:
            raise Exception("Not yet implemented")
        tasks = {"stop": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return {'status': False, 'errors': e.__str__()}
        logger.debug("output : " + str(response))
        return {'status': True}

    def reload(self):
        if self.server.os.name == 'debian':
            command = settings.OSSEC_BINARY + "/ossec-control reload"
        else:
            raise Exception("Not yet implemented")
        tasks = {"reload": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return {'status': False, 'errors': e.__str__()}
        logger.debug("output : " + str(response))
        return {'status': True}

    def status(self):
        if self.server.os.name == 'debian':
            command = settings.OSSEC_BINARY + "/ossec-control status"
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

    def deploy_conf(self):
        errors = list()
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
                                    dest=settings.OSSEC_CONFIG,
                                    become=True
                                    )
            logger.debug("output : " + str(response))
        except Exception as e:
            logger.error(e)
            deploy = False
            errors.append(e.__str__())
        if os.path.isfile(tmpdir + 'temp.conf'):
            os.remove(tmpdir + "temp.conf")
        if deploy:
            return {'status': True}
        else:
            return {'status': deploy, 'errors': errors}


class OssecServer(Ossec):
    """
    Stores an instance of Ossec server IDS software.
    """
    rulesets = models.ManyToManyField(RuleSetOssec, blank=True)

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
            command1 = settings.OSSEC_BINARY + "/ossec-monitord -t"
            command2 = settings.OSSEC_BINARY + "/ossec-remoted -t"
        else:
            raise Exception("Not yet implemented")

        tasks = {"test monitord": command1, "test remoted": command2}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return True

    def list_agents(self):
        if self.server.os.name == 'debian':
            command = settings.OSSEC_BINARY + "/list_agents -a"
        else:
            raise Exception("Not yet implemented")

        tasks = {"list agents": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return response

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


class OssecAgent(Ossec):
    """
    Stores an instance of Ossec agent IDS software.
    """
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
            command1 = settings.OSSEC_BINARY + "/ossec-monitord -t"
            command2 = settings.OSSEC_BINARY + "/ossec-agentd -t"

        else:
            raise Exception("Not yet implemented")
        tasks = {"test monitord": command1, "test remoted": command2}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e.__str__())
            return False
        logger.debug("output : " + str(response))
        return True

    def install(self):
        version = settings.OSSEC_VERSION
        if self.server.os.name == 'debian':
            command1 = "wget https://github.com/ossec/ossec-hids/archive/" + version + ".tar.gz"
            command2 = "tar xf " + version + ".tar.gz"
            command3 = "cp probemanager/ossec/preloaded-vars-agent.conf ossec-hids-" + version + "/etc/preloaded-vars.conf && chmod +x ossec-hids-" + version + "/etc/preloaded-vars.conf"
            command4 = "(cd ossec-hids-" + version + "/ && sudo ./install.sh)"
            command5 = "rm " + version + ".tar.gz && rm -rf ossec-hids-" + version
            command6 = "sudo cp probemanager/ossec/ossec-conf-agent.xml /var/ossec/etc/ossec.conf"
            command7 = settings.OSSEC_BINARY + "/agent-auth -m " + settings.OSSEC_SERVER_IP
        else:
            raise Exception("Not yet implemented")
        tasks = {"wget": command1, "tar": command2, "cp install conf": command3, "install": command4, "clean": command5, "cp conf": command6, "record to server": command7}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
            logger.error(e)
            return False
        logger.debug("output : " + str(response))
        return True

    def update(self):
        return self.install()


def increment_sid():
    last_sid = RuleUtility.objects.all().order_by('id').last()
    if not last_sid:
        return 50000000
    else:
        return last_sid.sid + 1


class RuleUtility(models.Model):
    """
    Execute a command like util.sh of Ossec IDS software.
    """
    TYPE_ACTION = (
        ("addfile", "addfile"),
        ("addsite", "addsite"),
        ("adddns", "adddns"),
    )
    LOG_FORMAT = (
        ("syslog", "syslog"),
        ("snort-full", "snort-full"),
        ("snort-fast", "snort-fast"),
        ("squid", "squid"),
        ("iis", "iis"),
        ("eventlog", "eventlog"),
        ("eventchannel", "eventchannel"),
        ("mysql_log", "mysql_log"),
        ("postgresql_log", "postgresql_log"),
        ("nmapg", "nmapg"),
        ("apache", "apache"),
        ("command", "command"),
        ("full_command", "full_command"),
        ("djb-multilog", "djb-multilog"),
        ("multi-line", "multi-line"),
    )
    ossec = models.ForeignKey(OssecAgent)
    sid = models.IntegerField(unique=True, editable=False, null=False, default=increment_sid)
    action = models.CharField(max_length=255, choices=TYPE_ACTION)
    log_format = models.CharField(max_length=255, choices=LOG_FORMAT, blank=True, null=True)
    option = models.CharField(max_length=400, verbose_name="Domain/Log path")

    def __str__(self):
        return self.ossec.name + "  " + self.action + " : " + self.option

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

    def create(self):
        # Problem Rule not assigned directly to a ossec agent, it's via ruleset
        template_addfile = Template("""<ossec_config>
    <localfile>
      <log_format>{{ log_format }}</log_format>
      <location>{{ path_log }}</location>
    </localfile>
</ossec_config>""")
        template_adddns_conf = Template("""<ossec_config>
    <localfile>
      <log_format>full_command</log_format>
      <command>host -W 5 -t NS {{ domain }}; host -W 5 -t A {{ domain }} | sort</command>
    </localfile>
</ossec_config>""")
        template_adddns_rule = Template("""<group name="local,dnschanges,">
    <rule id="{{ id }}" level="0">
      <if_sid>530</if_sid>
      <check_diff />
      <match>^ossec: output: 'host -W 5 -t NS {{ domain }}</match>
      <description>DNS Changed for {{ domain }}</description>
    </rule>
</group>""")
        template_addsite_conf = Template("""<ossec_config>
    <localfile>
      <log_format>full_command</log_format>
      <command>lynx --connect_timeout 10 --dump {{ site }} | head -n 10</command>
    </localfile>
</ossec_config>""")
        template_addsite_rule = Template("""<group name="local,sitechange,">
    <rule id="{{ id }}" level="0">
      <if_sid>530</if_sid>
      <check_diff />
      <match>^ossec: output: 'lynx --connect_timeout 10 --dump {{ site }}</match>
      <description>DNS Changed for {{ site }}</description>
    </rule>
</group>""")
        if self.action is 'addfile':
            final_addfile_conf = template_addfile.render(log_format=self.log_format, path_log=self.option)
            self.ossec.configuration.conf_file_text += os.linesep + final_addfile_conf + os.linesep
            self.save()
            return final_addfile_conf
        elif self.action is 'adddns':
            final_adddns_conf = template_adddns_conf.render(domain=self.option)
            final_adddns_rule = template_adddns_rule.render(domain=self.option, id=self.sid)
            self.ossec.configuration.conf_file_text += os.linesep + final_adddns_conf + os.linesep
            self.save()
            rule = RuleOssec(rev=1, reference="Rule utility, adddns", rule_full=final_adddns_rule, created_date=timezone.now())
            rule.save()
            return final_adddns_conf, final_adddns_rule
        elif self.action is 'addsite':
            final_addsite_conf = template_addsite_conf.render(site=self.option)
            final_addsite_rule = template_addsite_rule.render(site=self.option, id=self.sid)
            self.ossec.configuration.conf_file_text += os.linesep + final_addsite_conf + os.linesep
            self.save()
            rule = RuleOssec(rev=1, reference="Rule utility, addsite", rule_full=final_addsite_rule, created_date=timezone.now())
            rule.save()

            return final_addsite_conf, final_addsite_rule
