===================
django-allauth-adfs
===================

.. image:: https://travis-ci.org/thenewguy/django-allauth-adfs.svg?branch=master
    :target: https://travis-ci.org/thenewguy/django-allauth-adfs

.. image:: https://ci.appveyor.com/api/projects/status/hy58o1x9hopfej6k?svg=true
    :target: https://ci.appveyor.com/project/thenewguy/django-allauth-adfs

.. image:: https://coveralls.io/repos/thenewguy/django-allauth-adfs/badge.svg?branch=master
    :target: https://coveralls.io/github/thenewguy/django-allauth-adfs?branch=master

.. image:: https://badge.fury.io/py/django-allauth-adfs.svg
    :target: http://badge.fury.io/py/django-allauth-adfs

============
installation
============

apt-get update && apt-get install -y libffi-dev libssl-dev

pip install django-allauth-adfs django-allauth-adfs[jwt] django-allauth-adfs[pki]

if you want to enforce staff users to log in via adfs
add allauth_adfs to installed apps and set
SOCIALACCOUNT_ADAPTER = "allauth_adfs.socialaccount.adapter.SocialAccountAdapter"

if you want to return different django user instances per SocialApp from the provider
use utils.per_social_app_extract_uid_handler instead of the default_extract_uid_handler
this can be useful for permissions handling in multi tenant configurations
and utils.per_social_app_extract_common_fields_handler for the username to be based
on app id. it uses base64 guid and app id.

if you want the admin to use this auth then you do the following:
AUTHENTICATION_BACKENDS = [
    'allauth.account.auth_backends.AuthenticationBackend',
]

then somewhere in admin.py for an app

from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import admin

admin.autodiscover()

# monkey patch admin login view to redirect to the site login view
admin.site.login = login_required(
    staff_member_required(admin.site.login, login_url="permission-denied-change-user")
)

the "permission-denied-change-user" view is just a view that presents a message via the messages framework
to the user about why they are being redirected and then redirects to the sign out view.

============
testing
============

cd vagrant/
vagrant up
vagrant ssh
cd vagrant/

# note we move TOX_WORK_DIR outside of the vagrant synced folder to increase performance
TOX_WORK_DIR=/tmp tox -vv

-- or test one environment and skip the coverage report --

SUPPRESS_COVERAGE_REPORT="--suppress-coverage-report" TOX_WORK_DIR="/tmp" tox -vv -e py36-django-20 
