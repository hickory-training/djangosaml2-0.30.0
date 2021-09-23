# Copyright (C) 2012 Sam Bull (lsb@pocketuniverse.ca)
# Copyright (C) 2011-2012 Yaco Sistemas (http://www.yaco.es)
# Copyright (C) 2010 Lorenzo Gil Sanchez <lorenzo.gil.sanchez@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User as DjangoUserModel
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

from djangosaml2.backends import Saml2Backend, set_attribute

from .models import TestUser


class BackendUtilMethodsTests(TestCase):

    def test_set_attribute(self):
        u = TestUser()
        self.assertFalse(hasattr(u, 'custom_attribute'))

        # Set attribute initially
        changed = set_attribute(u, 'custom_attribute', 'value')
        self.assertTrue(changed)
        self.assertEqual(u.custom_attribute, 'value')

        # 'Update' to the same value again
        changed_same = set_attribute(u, 'custom_attribute', 'value')
        self.assertFalse(changed_same)
        self.assertEqual(u.custom_attribute, 'value')

        # Update to a different value
        changed_different = set_attribute(u, 'custom_attribute', 'new_value')
        self.assertTrue(changed_different)
        self.assertEqual(u.custom_attribute, 'new_value')


class Saml2BackendTests(TestCase):
    """ UnitTests on backend classes
    """
    backend_cls = Saml2Backend

    def setUp(self):
        self.backend = self.backend_cls()
        self.user = TestUser.objects.create(username='john')

    def test_get_model_ok(self):
        self.assertEqual(self.backend._user_model, TestUser)

    def test_get_model_nonexisting(self):
        with override_settings(SAML_USER_MODEL='testprofiles.NonExisting'):
            with self.assertRaisesMessage(ImproperlyConfigured, "Model 'testprofiles.NonExisting' could not be loaded"):
                self.assertEqual(self.backend._user_model, None)

    def test_get_model_invalid_specifier(self):
        with override_settings(SAML_USER_MODEL='random_package.specifier.testprofiles.NonExisting'):
            with self.assertRaisesMessage(ImproperlyConfigured, "Model was specified as 'random_package.specifier.testprofiles.NonExisting', but it must be of the form 'app_label.model_name'"):
                self.assertEqual(self.backend._user_model, None)

    def test_user_model_specified(self):
        with override_settings(AUTH_USER_MODEL='auth.User'):
            with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
                self.assertEqual(self.backend._user_model, TestUser)

    def test_user_model_default(self):
        with override_settings(AUTH_USER_MODEL='auth.User'):
            self.assertEqual(self.backend._user_model, DjangoUserModel)

    def test_user_lookup_attribute_specified(self):
        with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
            with override_settings(SAML_DJANGO_USER_MAIN_ATTRIBUTE='age'):
                self.assertEqual(self.backend._user_lookup_attribute, 'age')

    def test_user_lookup_attribute_default(self):
        with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
            self.assertEqual(self.backend._user_lookup_attribute, 'username')

    def test_is_authorized(self):
        self.assertTrue(self.backend.is_authorized({}, {}))

    def test_clean_attributes(self):
        attributes = {'random': 'dummy', 'value': 123}
        self.assertEqual(self.backend.clean_attributes(attributes), attributes)
        
    def test_clean_user_main_attribute(self):
        self.assertEqual(self.backend.clean_user_main_attribute('value'), 'value')

    def test_update_user(self):
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': ('Doe', ),
            }
        self.backend._update_user(self.user, attributes, attribute_mapping)
        self.assertEqual(self.user.email, 'john@example.com')
        self.assertEqual(self.user.first_name, 'John')
        self.assertEqual(self.user.last_name, 'Doe')

        attribute_mapping['saml_age'] = ('age', )
        attributes['saml_age'] = ('22', )
        self.backend._update_user(self.user, attributes, attribute_mapping)
        self.assertEqual(self.user.age, '22')

    def test_update_user_callable_attributes(self):
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('process_first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': ('Doe', ),
            }
        self.backend._update_user(self.user, attributes, attribute_mapping)
        self.assertEqual(self.user.email, 'john@example.com')
        self.assertEqual(self.user.first_name, 'John')
        self.assertEqual(self.user.last_name, 'Doe')

    def test_update_user_empty_attribute(self):
        self.user.last_name = 'Smith'
        self.user.save()

        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': (),
            }
        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            self.backend._update_user(self.user, attributes, attribute_mapping)
        self.assertEqual(self.user.email, 'john@example.com')
        self.assertEqual(self.user.first_name, 'John')
        # empty attribute list: no update
        self.assertEqual(self.user.last_name, 'Smith')
        self.assertIn(
            'DEBUG:djangosaml2:Could not find value for "sn", not updating fields "(\'last_name\',)"',
            logs.output,
        )

    def test_invalid_model_attribute_log(self):
        attribute_mapping = {
            'uid': ['username'],
            'cn': ['nonexistent'],
        }
        attributes = {
            'uid': ['john'],
            'cn': ['John'],
        }

        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            user, _ = self.backend.get_or_create_user(self.backend._user_lookup_attribute, 'john', True, None, None, None, None)
            self.backend._update_user(user, attributes, attribute_mapping)

        self.assertIn(
            'DEBUG:djangosaml2:Could not find attribute "nonexistent" on user "john"',
            logs.output,
        )

    @override_settings(SAML_USER_MODEL='testprofiles.RequiredFieldUser')
    def test_create_user_with_required_fields(self):
        attribute_mapping = {
            'mail': ['email'],
            'mail_verified': ['email_verified']
        }
        attributes = {
            'mail': ['john@example.org'],
            'mail_verified': [True],
        }
        # User creation does not fail if several fields are required.
        user, created = self.backend.get_or_create_user(self.backend._user_lookup_attribute, 'john@example.org', True, None, None, None, None)

        self.assertEquals(user.email, 'john@example.org')
        self.assertIs(user.email_verified, None)

        user = self.backend._update_user(user, attributes, attribute_mapping, created)
        self.assertIs(user.email_verified, True)

    def test_django_user_main_attribute(self):
        old_username_field = get_user_model().USERNAME_FIELD
        get_user_model().USERNAME_FIELD = 'slug'
        self.assertEqual(self.backend._user_lookup_attribute, 'slug')
        get_user_model().USERNAME_FIELD = old_username_field

        with override_settings(AUTH_USER_MODEL='auth.User'):
            self.assertEqual(
                DjangoUserModel.USERNAME_FIELD,
                self.backend._user_lookup_attribute)

        with override_settings(
                AUTH_USER_MODEL='testprofiles.StandaloneUserModel'):
            self.assertEqual(
                self.backend._user_lookup_attribute,
                'username')

        with override_settings(SAML_DJANGO_USER_MAIN_ATTRIBUTE='foo'):
            self.assertEqual(self.backend._user_lookup_attribute, 'foo')

    def test_get_or_create_user_existing(self):
        with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
            user, created = self.backend.get_or_create_user(self.backend._user_lookup_attribute, 'john', False, None, None, None, None)

        self.assertTrue(isinstance(user, TestUser))
        self.assertFalse(created)

    def test_get_or_create_user_duplicates(self):
        TestUser.objects.create(username='paul')

        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
                user, created = self.backend.get_or_create_user('age', '', False, None, None, None, None)

        self.assertTrue(user is None)
        self.assertFalse(created)
        self.assertIn(
            "ERROR:djangosaml2:Multiple users match, model: testprofiles.testuser, lookup: {'age': ''}",
            logs.output,
        )

    def test_get_or_create_user_no_create(self):
        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
                user, created = self.backend.get_or_create_user(self.backend._user_lookup_attribute, 'paul', False, None, None, None, None)

        self.assertTrue(user is None)
        self.assertFalse(created)
        self.assertIn(
            "ERROR:djangosaml2:The user does not exist, model: testprofiles.testuser, lookup: {'username': 'paul'}",
            logs.output,
        )

    def test_get_or_create_user_create(self):
        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            with override_settings(SAML_USER_MODEL='testprofiles.TestUser'):
                user, created = self.backend.get_or_create_user(self.backend._user_lookup_attribute, 'paul', True, None, None, None, None)

        self.assertTrue(isinstance(user, TestUser))
        self.assertTrue(created)
        self.assertIn(
            "DEBUG:djangosaml2:New user created: {}".format(user),
            logs.output,
        )


class CustomizedBackend(Saml2Backend):
    """ Override the available methods with some customized implementation to test customization
    """
    def is_authorized(self, attributes, attribute_mapping):
        ''' Allow only staff users from the IDP '''
        return attributes.get('is_staff', (None, ))[0] == True
    
    def clean_attributes(self, attributes: dict) -> dict:
        ''' Keep only age attribute '''
        return {
            'age': attributes.get('age', (None, )),
            'is_staff': attributes.get('is_staff', (None, )),
            'uid': attributes.get('uid', (None, )),
        }

    def clean_user_main_attribute(self, main_attribute):
        ''' Replace all spaces an dashes by underscores '''
        return main_attribute.replace('-', '_').replace(' ', '_')


class CustomizedSaml2BackendTests(Saml2BackendTests):
    backend_cls = CustomizedBackend

    def test_is_authorized(self):
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': ('Doe', ),
            }
        self.assertFalse(self.backend.is_authorized(attributes, attribute_mapping))
        attributes['is_staff'] = (True, )
        self.assertTrue(self.backend.is_authorized(attributes, attribute_mapping))

    def test_clean_attributes(self):
        attributes = {'random': 'dummy', 'value': 123, 'age': '28'}
        self.assertEqual(self.backend.clean_attributes(attributes), {'age': '28', 'is_staff': (None,), 'uid': (None,)})
        
    def test_clean_user_main_attribute(self):
        self.assertEqual(self.backend.clean_user_main_attribute('va--l__ u -e'), 'va__l___u__e')

    def test_authenticate(self):
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            'age': ('age', ),
            'is_staff': ('is_staff', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': ('Doe', ),
            'age': ('28', ),
            'is_staff': (True, ),
            }

        self.assertEqual(self.user.age, '')
        self.assertEqual(self.user.is_staff, False)

        user = self.backend.authenticate(
            None,
            session_info={'ava': attributes, 'issuer': 'dummy_entity_id'},
            attribute_mapping=attribute_mapping,
        )

        self.assertEqual(user, self.user)

        self.user.refresh_from_db()
        self.assertEqual(self.user.age, '28')
        self.assertEqual(self.user.is_staff, True)
