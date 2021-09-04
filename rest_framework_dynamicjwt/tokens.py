from datetime import timedelta
from uuid import uuid4

from django.conf import settings
from django.utils.translation import gettext_lazy as _

from .backends import TokenBackend
from .exceptions import TokenBackendError, TokenError
from .models import AuthenticationSettingsModel
from .token_blacklist.models import BlacklistedToken, OutstandingToken
from .utils import (aware_utcnow, datetime_from_epoch, datetime_to_epoch,
                    format_lazy)


class Token:
    """
    A class which validates and wraps an existing JWT or can be used to build a
    new JWT.
    """
    token_type = None

    def __init__(self, authentication_settings: AuthenticationSettingsModel, token=None, verify=True):
        """
        !!!! IMPORTANT !!!! MUST raise a TokenError with a user-facing error
        message if the given token is invalid, expired, or otherwise not safe
        to use.
        """
        
        if self.token_type is None:
            raise TokenError(_('Cannot create token with no type'))

        self.should_verify = verify
        self.token = token
        self.current_time = aware_utcnow()
        self.authentication_settings = authentication_settings
        
        self.lifetime = timedelta(seconds=0)
    
    def post_init(self):
        # Set up token
        if self.token is not None:
            # An encoded token was provided
            token_backend = self.get_token_backend()

            # Decode token
            try:
                self.payload = token_backend.decode(self.token, verify=self.should_verify)
            except TokenBackendError:
                raise TokenError(_('Token is invalid or expired'))

            if self.should_verify:
                self.verify()
        else:
            # New token.  Skip all the verification steps.
            self.payload = {
                self.authentication_settings.token_type_claim: self.token_type}

            # Set "exp" claim with default value
            self.set_exp(from_time=self.current_time, lifetime=self.lifetime)

            # Set "jti" claim
            self.set_jti()

    def __repr__(self):
        return repr(self.payload)

    def __getitem__(self, key):
        return self.payload[key]

    def __setitem__(self, key, value):
        self.payload[key] = value

    def __delitem__(self, key):
        del self.payload[key]

    def __contains__(self, key):
        return key in self.payload

    def get(self, key, default=None):
        return self.payload.get(key, default)

    def __str__(self):
        """
        Signs and returns a token as a base64 encoded string.
        """
        return self.get_token_backend().encode(self.payload)

    def verify(self):
        """
        Performs additional validation steps which were not performed when this
        token was decoded.  This method is part of the "public" API to indicate
        the intention that it may be overridden in subclasses.
        """
        # According to RFC 7519, the "exp" claim is OPTIONAL
        # (https://tools.ietf.org/html/rfc7519#section-4.1.4).  As a more
        # correct behavior for authorization tokens, we require an "exp"
        # claim.  We don't want any zombie tokens walking around.
        self.check_exp()

        # Ensure token id is present
        if self.authentication_settings.jti_claim not in self.payload:
            raise TokenError(_('Token has no id'))

        self.verify_token_type()

    def verify_token_type(self):
        """
        Ensures that the token type claim is present and has the correct value.
        """
        try:
            token_type = self.payload[self.authentication_settings.token_type_claim]
        except KeyError:
            raise TokenError(_('Token has no type'))

        if self.token_type != token_type:
            raise TokenError(_('Token has wrong type'))

    def set_jti(self):
        """
        Populates the configured jti claim of a token with a string where there
        is a negligible probability that the same string will be chosen at a
        later time.

        See here:
        https://tools.ietf.org/html/rfc7519#section-4.1.7
        """
        self.payload[self.authentication_settings.jti_claim] = uuid4().hex

    def set_exp(self, claim='exp', from_time=None, lifetime=None):
        """
        Updates the expiration time of a token.
        """
        if from_time is None:
            from_time = self.current_time

        if lifetime is None:
            lifetime = self.lifetime

        self.payload[claim] = datetime_to_epoch(from_time + lifetime)

    def check_exp(self, claim='exp', current_time=None):
        """
        Checks whether a timestamp value in the given claim has passed (since
        the given datetime value in `current_time`).  Raises a TokenError with
        a user-facing error message if so.
        """
        if current_time is None:
            current_time = self.current_time

        try:
            claim_value = self.payload[claim]
        except KeyError:
            raise TokenError(format_lazy(_("Token has no '{}' claim"), claim))

        claim_time = datetime_from_epoch(claim_value)
        if claim_time <= current_time:
            raise TokenError(format_lazy(
                _("Token '{}' claim has expired"), claim))

    @classmethod
    def for_user(cls, authentication_settings: AuthenticationSettingsModel, user):
        """
        Returns an authorization token for the given user that will be provided
        after authenticating the user's credentials.
        """
        
        user_id = getattr(user, authentication_settings.user_id_field)
        if not isinstance(user_id, int):
            user_id = str(user_id)

        token = cls(authentication_settings=authentication_settings)
        token[authentication_settings.user_id_claim] = user_id

        return token

    def get_token_backend(self):
        return TokenBackend(self.authentication_settings)


class BlacklistMixin:
    """
    If the `rest_framework_simplejwt.token_blacklist` app was configured to be
    used, tokens created from `BlacklistMixin` subclasses will insert
    themselves into an outstanding token list and also check for their
    membership in a token blacklist.
    """
    if 'rest_framework_simplejwt.token_blacklist' in settings.INSTALLED_APPS:
        def verify(self, *args, **kwargs):
            self.check_blacklist()

            super().verify(*args, **kwargs)

        def check_blacklist(self):
            """
            Checks if this token is present in the token blacklist.  Raises
            `TokenError` if so.
            """
            jti = self.payload[self.authentication_settings.jti_claim]

            if BlacklistedToken.objects.filter(token__jti=jti).exists():
                raise TokenError(_('Token is blacklisted'))

        def blacklist(self):
            """
            Ensures this token is included in the outstanding token list and
            adds it to the blacklist.
            """
            jti = self.payload[self.authentication_settings.jti_claim]
            exp = self.payload['exp']

            # Ensure outstanding token exists with given jti
            token, _ = OutstandingToken.objects.get_or_create(
                jti=jti,
                authentication_settings=self.authentication_settings,
                defaults={
                    'token': str(self),
                    'expires_at': datetime_from_epoch(exp),
                },
            )

            return BlacklistedToken.objects.get_or_create(token=token)

        @classmethod
        def for_user(cls, authentication_settings: AuthenticationSettingsModel, user):
            """
            Adds this token to the outstanding token list.
            """
            token = super().for_user(authentication_settings, user)

            jti = token[authentication_settings.jti_claim]
            exp = token['exp']

            OutstandingToken.objects.create(
                user=user,
                jti=jti,
                authentication_settings=authentication_settings,
                token=str(token),
                created_at=token.current_time,
                expires_at=datetime_from_epoch(exp),
            )

            return token


class SlidingToken(BlacklistMixin, Token):
    token_type = 'sliding'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.lifetime = timedelta(
                self.authentication_settings.sliding_token_lifetime)
        
        self.post_init()

        if self.token is None:
            # Set sliding refresh expiration claim if new token
            self.set_exp(
                self.authentication_settings.sliding_token_refresh_exp_claim,
                from_time=self.current_time,
                lifetime=self.authentication_settings.sliding_token_refresh_lifetime,
            )


class RefreshToken(BlacklistMixin, Token):
    token_type = 'refresh'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.lifetime = timedelta(
                self.authentication_settings.refresh_token_lifetime)
        
        self.post_init()

        self.no_copy_claims = (
            self.authentication_settings.token_type_claim,
            'exp',

            # Both of these claims are included even though they may be the same.
            # It seems possible that a third party token might have a custom or
            # namespaced JTI claim as well as a default "jti" claim.  In that case,
            # we wouldn't want to copy either one.
            self.authentication_settings.jti_claim,
            'jti',
        )

    @property
    def access_token(self):
        """
        Returns an access token created from this refresh token.  Copies all
        claims present in this refresh token to the new access token except
        those claims listed in the `no_copy_claims` attribute.
        """
        access = AccessToken(self.authentication_settings)

        # Use instantiation time of refresh token as relative timestamp for
        # access token "exp" claim.  This ensures that both a refresh and
        # access token expire relative to the same time if they are created as
        # a pair.
        access.set_exp(from_time=self.current_time)

        no_copy = self.no_copy_claims
        for claim, value in self.payload.items():
            if claim in no_copy:
                continue
            access[claim] = value

        return access


class AccessToken(Token):
    token_type = 'access'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.lifetime = timedelta(
                self.authentication_settings.access_token_lifetime)

        self.post_init()


class UntypedToken(Token):
    token_type = 'untyped'

    def verify_token_type(self):
        """
        Untyped tokens do not verify the "token_type" claim.  This is useful
        when performing general validation of a token's signature and other
        properties which do not relate to the token's intended use.
        """
        pass
