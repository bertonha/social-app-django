"""Django ORM models for Social Auth"""

import base64
import time
from datetime import datetime, timedelta

from django.core.exceptions import FieldDoesNotExist
from django.db import router, transaction
from django.db.utils import IntegrityError
from social_core.storage import (
    AssociationMixin,
    BaseStorage,
    CodeMixin,
    NonceMixin,
    PartialMixin,
    UserMixin,
)


class DjangoUserMixin(UserMixin):
    """Social Auth association model"""

    @classmethod
    def changed(cls, user):
        user.save()

    def set_extra_data(self, extra_data=None):
        if extra_data and self.extra_data != extra_data:
            if self.extra_data and not isinstance(self.extra_data, str):
                self.extra_data.update(extra_data)
            else:
                self.extra_data = extra_data
            self.extra_data_new = self.extra_data
            self.save()

    @property
    def access_token(self):
        """Return access_token stored in extra_data or None"""
        return self.extra_data.get("access_token", self.extra_data_new.get("access_token"))

    def refresh_token(self, strategy, *args, **kwargs):
        token = self.extra_data.get("refresh_token", self.extra_data_new.get("refresh_token")) or self.access_token
        backend = self.get_backend_instance(strategy)
        if token and backend and hasattr(backend, "refresh_token"):
            response = backend.refresh_token(token, *args, **kwargs)
            extra_data = backend.extra_data(self, self.uid, response, self.extra_data)
            if self.set_extra_data(extra_data):
                self.save()

    def get_expires(self) -> int | None:
        if self.extra_data and "expires" in self.extra_data:
            try:
                return int(self.extra_data.get("expires"))
            except (ValueError, TypeError):
                return None
        elif self.extra_data_new and "expires" in self.extra_data_new:
            try:
                return int(self.extra_data_new.get("expires"))
            except (ValueError, TypeError):
                return None

        return None

    def expiration_timedelta(self):
        """Return provider session live seconds. Returns a timedelta ready to
        use with session.set_expiry().

        If provider returns a timestamp instead of session seconds to live, the
        timedelta is inferred from current time (using UTC timezone). None is
        returned if there's no value stored or it's invalid.
        """
        expires = self.get_expires()
        if expires is None:
            return None


        now = datetime.utcnow()

        # Detect if expires is a timestamp
        if expires > time.mktime(now.timetuple()):
            # expires is a datetime, return the remaining difference
            return datetime.utcfromtimestamp(expires) - now
        else:
            # expires is the time to live seconds since creation,
            # check against auth_time if present, otherwise return
            # the value
            auth_time = self.extra_data.get("auth_time", self.extra_data_new.get("auth_time"))
            if auth_time:
                reference = datetime.utcfromtimestamp(auth_time)
                return (reference + timedelta(seconds=expires)) - now
            else:
                return timedelta(seconds=expires)

    @classmethod
    def allowed_to_disconnect(cls, user, backend_name, association_id=None):
        if association_id is not None:
            qs = cls.objects.exclude(id=association_id)
        else:
            qs = cls.objects.exclude(provider=backend_name)
        qs = qs.filter(user=user)

        if hasattr(user, "has_usable_password"):
            valid_password = user.has_usable_password()
        else:
            valid_password = True
        return valid_password or qs.exists()

    @classmethod
    def disconnect(cls, entry):
        entry.delete()

    @classmethod
    def username_field(cls):
        return getattr(cls.user_model(), "USERNAME_FIELD", "username")

    @classmethod
    def user_exists(cls, *args, **kwargs):
        """
        Return True/False if a User instance exists with the given arguments.
        Arguments are directly passed to filter() manager method.
        """
        if "username" in kwargs:
            kwargs[cls.username_field()] = kwargs.pop("username")
        return cls.user_model()._default_manager.filter(*args, **kwargs).exists()

    @classmethod
    def get_username(cls, user):
        return getattr(user, cls.username_field(), None)

    @classmethod
    def create_user(cls, *args, **kwargs):
        username_field = cls.username_field()
        if "username" in kwargs:
            if username_field not in kwargs:
                kwargs[username_field] = kwargs.pop("username")
            else:
                # If username_field is 'email' and there is no field named "username"
                # then latest should be removed from kwargs.
                try:
                    cls.user_model()._meta.get_field("username")
                except FieldDoesNotExist:
                    kwargs.pop("username")
        try:
            if hasattr(transaction, "atomic"):
                # In Django versions that have an "atomic" transaction decorator / context
                # manager, there's a transaction wrapped around this call.
                # If the create fails below due to an IntegrityError, ensure that the transaction
                # stays undamaged by wrapping the create in an atomic.
                using = router.db_for_write(cls.user_model())
                with transaction.atomic(using=using):
                    user = cls.user_model()._default_manager.create_user(*args, **kwargs)
            else:
                user = cls.user_model()._default_manager.create_user(*args, **kwargs)
        except IntegrityError as exc:
            # If email comes in as None it won't get found in the get
            if kwargs.get("email", True) is None:
                kwargs["email"] = ""
            try:
                user = cls.user_model()._default_manager.get(*args, **kwargs)
            except cls.user_model().DoesNotExist:
                raise exc
        return user

    @classmethod
    def get_user(cls, pk=None, **kwargs):
        if pk:
            kwargs = {"pk": pk}
        try:
            return cls.user_model()._default_manager.get(**kwargs)
        except cls.user_model().DoesNotExist:
            return None

    @classmethod
    def get_users_by_email(cls, email):
        user_model = cls.user_model()
        email_field = getattr(user_model, "EMAIL_FIELD", "email")
        return user_model._default_manager.filter(**{email_field + "__iexact": email})

    @classmethod
    def get_social_auth(cls, provider, uid):
        if not isinstance(uid, str):
            uid = str(uid)
        try:
            return cls.objects.get(provider=provider, uid=uid)
        except cls.DoesNotExist:
            return None

    @classmethod
    def get_social_auth_for_user(cls, user, provider=None, id=None):
        qs = cls.objects.filter(user=user)

        if provider:
            qs = qs.filter(provider=provider)

        if id:
            qs = qs.filter(id=id)
        return qs

    @classmethod
    def create_social_auth(cls, user, uid, provider):
        if not isinstance(uid, str):
            uid = str(uid)
        if hasattr(transaction, "atomic"):
            # In Django versions that have an "atomic" transaction decorator / context
            # manager, there's a transaction wrapped around this call.
            # If the create fails below due to an IntegrityError, ensure that the transaction
            # stays undamaged by wrapping the create in an atomic.
            using = router.db_for_write(cls)
            with transaction.atomic(using=using):
                social_auth = cls.objects.create(user=user, uid=uid, provider=provider)
        else:
            social_auth = cls.objects.create(user=user, uid=uid, provider=provider)
        return social_auth


class DjangoNonceMixin(NonceMixin):
    @classmethod
    def use(cls, server_url, timestamp, salt):
        return cls.objects.get_or_create(server_url=server_url, timestamp=timestamp, salt=salt)[1]

    @classmethod
    def get(cls, server_url, salt):
        return cls.objects.get(
            server_url=server_url,
            salt=salt,
        )

    @classmethod
    def delete(cls, nonce):
        nonce.delete()


class DjangoAssociationMixin(AssociationMixin):
    @classmethod
    def store(cls, server_url, association):
        # Don't use get_or_create because issued cannot be null
        try:
            assoc = cls.objects.get(server_url=server_url, handle=association.handle)
        except cls.DoesNotExist:
            assoc = cls(server_url=server_url, handle=association.handle)

        try:
            assoc.secret = base64.encodebytes(association.secret).decode()
        except AttributeError:
            assoc.secret = base64.encodestring(association.secret).decode()
        assoc.issued = association.issued
        assoc.lifetime = association.lifetime
        assoc.assoc_type = association.assoc_type
        assoc.save()

    @classmethod
    def get(cls, *args, **kwargs):
        return cls.objects.filter(*args, **kwargs)

    @classmethod
    def remove(cls, ids_to_delete):
        cls.objects.filter(pk__in=ids_to_delete).delete()


class DjangoCodeMixin(CodeMixin):
    @classmethod
    def get_code(cls, code):
        try:
            return cls.objects.get(code=code)
        except cls.DoesNotExist:
            return None


class DjangoPartialMixin(PartialMixin):
    @classmethod
    def load(cls, token):
        try:
            return cls.objects.get(token=token)
        except cls.DoesNotExist:
            return None

    @classmethod
    def destroy(cls, token):
        partial = cls.load(token)
        if partial:
            partial.delete()

    @property
    def args(self):
        return self.data.get("args", self.data_new.get("args", []))

    @args.setter
    def args(self, value):
        self.data["args"] = value
        self.data_new["args"] = value

    @property
    def kwargs(self):
        return self.data.get("kwargs", self.data_new.get("kwargs", {}))

    @kwargs.setter
    def kwargs(self, value):
        self.data["kwargs"] = value
        self.data_new["kwargs"] = value

    def extend_kwargs(self, values):
        self.data["kwargs"].update(values)
        self.data_new["kwargs"].update(values)

    @classmethod
    def prepare(cls, backend, next_step, data):
        partial = cls()
        partial.backend = backend
        partial.next_step = next_step
        partial.data = data
        partial.data_new = data
        partial.token = cls.generate_token()
        return partial


class BaseDjangoStorage(BaseStorage):
    user = DjangoUserMixin
    nonce = DjangoNonceMixin
    association = DjangoAssociationMixin
    code = DjangoCodeMixin
