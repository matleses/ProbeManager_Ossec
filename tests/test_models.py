""" venv/bin/python probemanager/manage.py test ossec.tests.test_models --settings=probemanager.settings.dev """
from django.conf import settings
from django.db import transaction
from django.db.utils import IntegrityError
from django.test import TestCase
from django.utils import timezone

from ossec.models import ConfOssecServer, ConfOssecAgent


class ConfigurationTest(TestCase):
    fixtures = ['init', 'crontab', 'test-bro-conf']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_conf_bro(self):
        all_conf_bro = ConfOssecServer.get_all()
        conf_bro = ConfOssecServer.get_by_id(101)
        self.assertEqual(len(all_conf_bro), 1)
        self.assertEqual(conf_bro.name, "test_bro_conf")
        self.assertEqual(conf_bro.my_scripts, "/usr/local/bro/share/bro/site/myscripts.bro")
        self.assertEqual(conf_bro.bin_directory, "/usr/local/bro/bin/")
        self.assertEqual(str(conf_bro), "test_bro_conf")
        conf_bro = ConfOssecServer.get_by_id(199)
        self.assertEqual(conf_bro, None)
        with self.assertRaises(IntegrityError):
            ConfOssecServer.objects.create(name="test_bro_conf")
