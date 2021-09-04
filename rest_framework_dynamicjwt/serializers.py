from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import update_last_login
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers
from rest_framework.exceptions import ErrorDetail, ValidationError
from rest_framework.fields import empty
from rest_framework.generics import get_object_or_404
from .models import AuthenticationSettingsModel

from .models import AuthenticationSettingsModel

from .settings import api_settings, default_authentication_settings
from .tokens import RefreshToken, SlidingToken, UntypedToken

from .token_blacklist.models import BlacklistedToken


class PasswordField(serializers.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('style', {})

        kwargs['style']['input_type'] = 'password'
        kwargs['write_only'] = True

        super().__init__(*args, **kwargs)


class AuthenticationSettingsSerializer(serializers.Serializer):
    """A serializer that takes an authentication_settings parameter
    If none specified will use default"""

    def __init__(self, instance=None, data=empty, **kwargs):
        if 'authentication_settings' in kwargs:
            self.authentication_settings = kwargs.pop('authentication_settings')
        else:
            self.authentication_settings = default_authentication_settings
        super().__init__(instance=instance, data=data, **kwargs)


class TokenObtainSerializer(AuthenticationSettingsSerializer):
    username_field = get_user_model().USERNAME_FIELD

    default_error_messages = {
        'no_active_account': _('No active account found with the given credentials')
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields[self.username_field] = serializers.CharField()
        self.fields['password'] = PasswordField()

    def validate(self, attrs):
        authenticate_kwargs = {
            self.username_field: attrs[self.username_field],
            'password': attrs['password'],
        }
        try:
            authenticate_kwargs['request'] = self.context['request']
        except KeyError:
            pass

        self.user = authenticate(**authenticate_kwargs)

        if not api_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed(
                self.error_messages['no_active_account'],
                'no_active_account',
            )

        return {}

    @classmethod
    def get_token(cls, authentication_settings, user):
        raise NotImplementedError(
            'Must implement `get_token` method for `TokenObtainSerializer` subclasses')


class TokenObtainPairSerializer(TokenObtainSerializer):
    def __int__(self, *args, **kwargs):
        super().init(*args, **kwargs)
        
    @classmethod
    def get_token(cls, authentication_settings, user):
        return RefreshToken.for_user(authentication_settings, user)

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.authentication_settings, self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        if self.authentication_settings.update_last_login:
            update_last_login(None, self.user)

        return data


class TokenObtainSlidingSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, authentication_settings, user):
        return SlidingToken.for_user(authentication_settings, user)

    def validate(self, attrs):
        data = super().validate(attrs)

        token = self.get_token(self.authentication_settings, self.user)

        data['token'] = str(token)

        if self.authentication_settings.u:
            update_last_login(None, self.user)

        return data


class TokenRefreshSerializer(AuthenticationSettingsSerializer):
    refresh = serializers.CharField()
    access = serializers.ReadOnlyField()

    def validate(self, attrs):
        refresh = RefreshToken(self.authentication_settings, attrs['refresh'])

        data = {'access': str(refresh.access_token)}

        if self.authentication_settings.rotate_refresh_tokens:
            if self.authentication_settings.blacklist_after_rotation:
                try:
                    # Attempt to blacklist the given refresh token
                    refresh.blacklist()
                except AttributeError:
                    # If blacklist app not installed, `blacklist` method will
                    # not be present
                    pass

            refresh.set_jti()
            refresh.set_exp()

            data['refresh'] = str(refresh)

        return data


class TokenRefreshSlidingSerializer(AuthenticationSettingsSerializer):
    token = serializers.CharField()

    def validate(self, attrs):
        token = SlidingToken(self.authentication_settings, attrs['token'])

        # Check that the timestamp in the "refresh_exp" claim has not
        # passed
        token.check_exp(self.authentication_settings.sliding_token_refresh_exp_claim)

        # Update the "exp" claim
        token.set_exp()

        return {'token': str(token)}


class TokenVerifySerializer(AuthenticationSettingsSerializer):
    token = serializers.CharField()

    def validate(self, attrs):
        token = UntypedToken(attrs['token'])

        if self.authentication_settings.blacklist_after_rotation:
            jti = token.get(self.authentication_settings.jti_claim)
            if BlacklistedToken.objects.filter(token__jti=jti).exists():
                raise ValidationError("Token is blacklisted")

        return {}


class AdminAuthenticationSettingsSerializer(serializers.ModelSerializer):
    """Admin authentication settings serializer"""

    class Meta:
        model = AuthenticationSettingsModel
        fields = '__all__'
