# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
from django.contrib.auth.backends import RemoteUserBackend
from pdns_app.user.user_manager import UserManager

class AliSSOUserBackend(RemoteUserBackend):
    """
    This backend is to be used in conjunction with the ``RemoteUserMiddleware``
    found in the middleware module of this package, and is used when the server
    is handling authentication outside of Django.

    By default, the ``authenticate`` method creates ``User`` objects for
    usernames that don't already exist in the database.  Subclasses can disable
    this behavior by setting the ``create_unknown_user`` attribute to
    ``False``.
    """
    def authenticate(self,username=None,first_name=None,last_name=None,email=None,buc_sso_id=None):
        """
        The username passed as ``remote_user`` is considered trusted.  This
        method simply returns the ``User`` object with the given username,
        creating a new ``User`` object if ``create_unknown_user`` is ``True``.

        Returns None if ``create_unknown_user`` is ``False`` and a ``User``
        object with the given username is not found in the database.
        """
        if not username:
            return
        user = None
        username = self.clean_username(username)

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if self.create_unknown_user:
            user, created = UserManager.buc_get_or_creat(username=username,first_name=first_name,last_name=last_name,email=email,buc_sso_id=buc_sso_id)
            if created:
                user = self.configure_user(user)
        else:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                pass
        return user

