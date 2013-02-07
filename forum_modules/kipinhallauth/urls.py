from django.utils.translation import ugettext as _
from django.conf.urls.defaults import patterns, url
from forum_modules.kipinhallauth.views import redirect_to_kipinhall_login,\
    kipinhall_profile

urlpatterns = patterns('',
    url(r'^%s%s%s$' % (_('account/'), _('kipinhall/'),  _('register/')), redirect_to_kipinhall_login, name='auth_kipinhall_register'),
    url(r'^%s%s%s%s$' % (_('account/'), _('kipinhall/'),  _('register/'), _('info/')), kipinhall_profile, name='auth_kipinhall_register_info'),
)