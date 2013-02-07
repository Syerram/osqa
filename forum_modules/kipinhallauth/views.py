import logging
import requests

from django.core.urlresolvers import reverse
from django.conf import settings
from django.http import HttpResponseRedirect

from forum.views.auth import login_and_forward
from django.contrib import messages
from django.shortcuts import render_to_response
from django.template.context import RequestContext

from forum.models.node import node_create
from forum.models import User, Question

log = logging.getLogger(__name__)


def post_to_kipinhall(instance, state):
    """
    Generic method that will post to kipinhall for update, brand new questions.
    """
    try:
        data = {'c': settings.KIPINHALL_AUTH_CLIENT_NAME, 'k': settings.KIPINHALL_AUTH_UNSALTED_KEY,
                'q_id': instance.id, 'name': instance.headline, 'owner': instance.user.username, 'description': instance.html[:20],
                'state': state}
        res = requests.post(settings.KIPINHALL_QA_SEND_UPDATE, data=data).json()
    except Exception as ex:
        log.error("Error occured attemtpting to update KH %s" % str(ex))


def add_question_event(instance, **kwargs):
    """
    delegation event called on question creation
    """
    post_to_kipinhall(instance, 'new')

node_create.connect(add_question_event, sender=Question)

def fetch_kipinhall_profile(tikcet):
    """
    performs a request to the server with the ticket
    """
    user_info = requests.get(settings.KIPINHALL_PROFILE_URL, params={'c': settings.KIPINHALL_AUTH_CLIENT_NAME, 
                                                                     'k': settings.KIPINHALL_AUTH_UNSALTED_KEY,
                                                                     'ticket': tikcet})
    return user_info.json()


def redirect_to_kipinhall_login(request):
    """
        Redirects users to the kipinhall login url, with two parsms
        1. callback url after login
        2. post url to post the user information
    """
    params = ['c=%s' % settings.KIPINHALL_AUTH_CLIENT_NAME, 
              'k=%s' % settings.KIPINHALL_AUTH_UNSALTED_KEY,  
              'u=%s' % reverse('auth_kipinhall_register_info')]

    url = u'{login}?{params}'.format(
                        login=settings.KIPINHALL_PROFILE_LOGIN_URL,
                        params='&'.join(params))

    log.info("Redirecting user to kipinhall profiles: {url}".format(url=url))
    return HttpResponseRedirect(redirect_to=url)

def kipinhall_profile(request):
    """
        redirect sent by kipinhall profile with the unique ID
    """
    # Create the user here => see local_auth signup code
    # add him/her to the request so its authenticated
    user_info = fetch_kipinhall_profile(request.GET['ticket'])
    forward = request.GET.get('url', reverse('index'))
    if user_info['result'] == 'ok':
        if request.user.is_authenticated():
            log.info("Same user, so lets just redirect and preserve session")
            return HttpResponseRedirect(redirect_to=forward)

        user_, created = User.objects.get_or_create(username=user_info['username'], email=user_info['email'])
        return login_and_forward(request, user_, forward)
    else:
        messages.add_message(request, messages.INFO, "Hmmm. Couldn't log you in. reason {reason}".format(reason=user_info['text']))
        return render_to_response('auth/auth_error.html', {}, context_instance=RequestContext(request))



