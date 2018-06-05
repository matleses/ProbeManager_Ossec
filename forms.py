from django.forms import ModelForm

from .models import ConfOssecServer


class ConfOssecServerSetForm(ModelForm):
    class Meta:
        model = ConfOssecServer
        fields = ('external_ip',
                  'conf_file_text',
                  )
