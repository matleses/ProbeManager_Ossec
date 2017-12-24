from django.db import models
# from home.ssh import execute, execute_copy
from home.models import Probe, ProbeConfiguration
import logging


logger = logging.getLogger('ossec')


class ConfOssec(ProbeConfiguration):

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
    # rulesets = models.ManyToManyField(RuleSetOssec, blank=True)
    configuration = models.ForeignKey(ConfOssec)

    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def __str__(self):
        return self.name + "  " + self.description
