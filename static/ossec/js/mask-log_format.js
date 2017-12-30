django.jQuery(document).ready(function(){
    if(django.jQuery( "#id_action option:selected" ).text() == 'addfile'){
        django.jQuery('.form-row.field-log_format').show();
    } else {
        django.jQuery('.form-row.field-log_format').hide();
    }
    django.jQuery('#id_action').change(function(){
        if(django.jQuery( "#id_action option:selected" ).text() == 'addfile'){
            django.jQuery('.form-row.field-log_format').show();
        } else {
            django.jQuery('.form-row.field-log_format').hide();
        }
    });
});
