import uuid

from django.contrib.auth import models as auth_models
from django.db import models
from django.db.models.manager import EmptyManager
from django.utils import timezone
from django.utils.functional import cached_property

from .compat import CallableFalse, CallableTrue
from .settings import api_settings


class TokenUser:
    """
    A dummy user class modeled after django.contrib.auth.models.AnonymousUser.
    Used in conjunction with the `JWTTokenUserAuthentication` backend to
    implement single sign-on functionality across services which share the same
    secret key.  `JWTTokenUserAuthentication` will return an instance of this
    class instead of a `User` model instance.  Instances of this class act as
    stateless user objects which are backed by validated tokens.
    """
    # User is always active since Dynamic JWT will never issue a token for an
    # inactive user
    is_active = True

    _groups = EmptyManager(auth_models.Group)
    _user_permissions = EmptyManager(auth_models.Permission)

    def __init__(self, token):
        self.token = token

    def __str__(self):
        return 'TokenUser {}'.format(self.id)

    @cached_property
    def id(self):
        return self.token[api_settings.USER_ID_CLAIM]

    @cached_property
    def pk(self):
        return self.id

    @cached_property
    def username(self):
        return self.token.get('username', '')

    @cached_property
    def is_staff(self):
        return self.token.get('is_staff', False)

    @cached_property
    def is_superuser(self):
        return self.token.get('is_superuser', False)

    def __eq__(self, other):
        return self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id)

    def save(self):
        raise NotImplementedError('Token users have no DB representation')

    def delete(self):
        raise NotImplementedError('Token users have no DB representation')

    def set_password(self, raw_password):
        raise NotImplementedError('Token users have no DB representation')

    def check_password(self, raw_password):
        raise NotImplementedError('Token users have no DB representation')

    @property
    def groups(self):
        return self._groups

    @property
    def user_permissions(self):
        return self._user_permissions

    def get_group_permissions(self, obj=None):
        return set()

    def get_all_permissions(self, obj=None):
        return set()

    def has_perm(self, perm, obj=None):
        return False

    def has_perms(self, perm_list, obj=None):
        return False

    def has_module_perms(self, module):
        return False

    @property
    def is_anonymous(self):
        return CallableFalse

    @property
    def is_authenticated(self):
        return CallableTrue

    def get_username(self):
        return self.username


class AuthenticationSettingsModel(models.Model):
    """Model that stores JWT config information"""

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    creation_time = models.DateTimeField(default=timezone.now)

    access_token_lifetime = models.PositiveBigIntegerField(
        default=api_settings.ACCESS_TOKEN_LIFETIME.total_seconds)
    refresh_token_lifetime = models.PositiveBigIntegerField(
        default=api_settings.REFRESH_TOKEN_LIFETIME.total_seconds)

    rotate_refresh_tokens = models.BooleanField(
        default=api_settings.ROTATE_REFRESH_TOKENS)
    blacklist_after_rotation = models.BooleanField(
        default=api_settings.BLACKLIST_AFTER_ROTATION)
    update_last_login = models.BooleanField(
        default=api_settings.UPDATE_LAST_LOGIN)

    class Algorithm(models.TextChoices):
        HS256 = 'HS256', 'HS256'
        HS384 = 'HS384', 'HS384'
        HS512 = 'HS512', 'HS512'
        RS256 = 'RS256', 'RS256'
        RS384 = 'RS384', 'RS384'
        RS512 = 'RS512', 'RS512'

    algorithm = models.CharField(
        max_length=5, choices=Algorithm.choices, default=api_settings.ALGORITHM)

    signing_key = models.TextField()
    verifying_key = models.TextField()

    audience = models.CharField(
        max_length=100, blank=True, default='' if api_settings.AUDIENCE == None else api_settings.AUDIENCE)
    issuer = models.CharField(max_length=100, blank=True,
                              default='' if api_settings.ISSUER == None else api_settings.ISSUER)
    jwk_url = models.CharField(
        max_length=500, blank=True, default='' if api_settings.JWK_URL == None else api_settings.JWK_URL)
    leeway = models.PositiveIntegerField(default=api_settings.LEEWAY)

    auth_header_name = models.CharField(
        max_length=50, default='' if api_settings.AUTH_HEADER_NAME is None else api_settings.AUTH_HEADER_NAME)
    user_id_field = models.CharField(
        max_length=50, default='' if api_settings.USER_ID_FIELD is None else api_settings.USER_ID_FIELD)
    user_id_claim = models.CharField(
        max_length=50, default='' if api_settings.USER_ID_CLAIM is None else api_settings.USER_ID_CLAIM)

    token_type_claim = models.CharField(
        max_length=20, default='' if api_settings.TOKEN_TYPE_CLAIM is None else api_settings.TOKEN_TYPE_CLAIM)
    jti_claim = models.CharField(
        max_length=20, default='' if api_settings.JTI_CLAIM is None else api_settings.JTI_CLAIM)

    sliding_token_refresh_exp_claim = models.CharField(
        max_length=50, default='' if api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM is None else api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM)
    sliding_token_lifetime = models.PositiveIntegerField(
        default=api_settings.SLIDING_TOKEN_LIFETIME.total_seconds)
    sliding_token_refresh_lifetime = models.PositiveIntegerField(
        default=api_settings.SLIDING_TOKEN_REFRESH_LIFETIME.total_seconds)

    class Meta:
        verbose_name = "Authentication Setting"
        verbose_name_plural = "Authentication Settings"

    def __str__(self):
        return str(self.id)
