Django REST Framework Dynamic JWT
==========

Abstract
--------

Dynamic JWT is a fork of the Dynamic JWT library for Django REST Framework enabling custom authentication settings eg different public keys timeouts etc for different requests.

Existing programs are compatible and default authentication settings specified in your setting.py file under the label DYNAMIC_JWT can still be used

I have maintained all other features of the Dynamic JWT library as closely as possible, I am a big fan of the project.

How does this project differ to Dynamic JWT?
------------------------------------------

JWT authentication requires an AuthenticationSettingsModel instance which stores previously non-unique settings.

A default version is passed to authentication serializers but you can pass one with the key-word argument authentication_settings when creating a serializer

You can save this AuthenticationSettingsModel instance in your database or other secure method

JWTs are saved in the database with a Foreign Key to their associated authentication settings

Dynamic JWT is a JSON Web Token authentication plugin for the `Django REST
Framework <http://www.django-rest-framework.org/>`__.

Do check out the Dynamic JWT docs as the settings used are the same as in Dynamic JWT `django-rest-framework-simplejwt.readthedocs.io
<https://django-rest-framework-simplejwt.readthedocs.io/en/latest/>`__.

