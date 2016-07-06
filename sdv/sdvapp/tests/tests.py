# ===================
# author: Peter Lacko
# year: 2016
# ===================

import unittest
from datetime import datetime, timedelta
from uuid import uuid4
from django.core.signing import Signer
from django.core.urlresolvers import reverse
from django.test import TestCase, Client
from sdvapp.models import (
    Certificate,
    Invitation,
    Organization,
    User,
    UserRole,
)
from sdvapp.utils import permissions, crypto
from sdvapp import exceptions

_private_key = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD7nLLFiEI+nHtB
PwuZU7uDLY7EN+Xm7vBHE8hPAL7gnCYVMomSmze7/UfzVqkOz6iQf7WB+tsOtp/F
Dd+ilEve01e0h49bNcLb+P7fouajQGP9r0nkxf5NT+BPkkpNbZIhO9rdOuYj5XbR
H/J4SEno2Ku4OQEH6zNRDh8v57AyWc5ntvv39OFUiBQ4+WaWrQ0DGj0Akkl6FpVG
ZcKlb1Wzw4mFMp9GpovfGcpsuJvarG1pTak1tRuUaNa29P8nm8wGzEjDTgOvOaxl
lik3zVGEicaFab7L53HCwuR7bXZTX0G+w2zNilqlIjPOx/Pf1dusofmYyqSa0fo6
9HOBNfuZAgMBAAECggEBAIu4q4mHrgmoycUkpmNBnSouHU6XH+LKosFFmgFND7IY
5Aj3ZG/2I9APyWm2oPCpnhiH4ppIXGbiQPyjRKG6qhsVz2lfsdrbktamgZpckqjr
M9uHAIi67gmupohpWzt98hzkaRhbAbvDS+S7UeE7e1eDInCNryXflUKYjfcDONPr
8xHANjndYQRVueSh2PaaJXdjaepPit0uU5Noec1Z5H2GeSfDoSSgU9rgrJE2xPdw
g7GoY1ZK7qBh1rwv1X8w0xzENlhPwuYLRzOLKcomUrmq9VTCYt0hhNRIwc29Ox+O
hRZn0UGYp5oHtUt9oZ1rQxTyYXfxhSXo0jt4kz5208UCgYEA/9w62WjT2HHvmK45
S+/pUoHJrKtXVY4jc2K5CJdfcVNFNHdmL+duX136bhHc56yQFkTjJLePv9mJrMkx
Xl116VNEDaUuvXn3D5wgVEAMiNkGz6H05x9Nzr+/3ogTK58T4STJehBFeJEUn58x
eHNfZ6pdHfpvGgtO1dPApXwGhesCgYEA+7/f4b6M1/E+LnF98v0fx3czP+lXecs0
IZa4CVcH/mE/FPZpNadPlKcwQtecCPE0RSzmHhxIVy7/f+4gPoGF/krzXOLAczxw
5YQbOj7nh5+pNcNjkZ9xemWg/D1f5i2lYH8ZUQ12AJwIAy3UaycniBci9OIyVzFm
e78Iw4ZXj4sCgYB3+MI3c2nyUepxAzCmpMYZA/aW2njHCzEgR6hPmPsN3mfS5DGs
QK6GVUC6H/IfR9EAQCjp7JCg+tYNiQF3KAfD8mE0rMGv4uKwFRsrpiS6flktPtnh
DdKkIVFMfS3QBHWD2oYGkF6i3BR5jGHcAu03ZLDo/6bc5XR/2xy3++HrJQKBgDG2
7HFZ/dpPC6aERwkLL5FmWrqOS/YDSOIxL1q40x1K+vgaySANUEvc0E0C4w9pApd+
jFr53tdIsrACyF9PmLRk/LYlGTgogWrxsabI8VP5FaNGWI1TXUd8dlQZkqyT6wqp
TsiQzfLE3VgzXrViYA4h84dEfAh3+vMJAKQMDZKNAoGAGUrA7lvguJ2SZ9mX47Ic
6zlv8a3Qte/hzssyFLxn8mOet3EJh8yEXTZpWwINYQlEABhY1RhuBSkdHCRS0/95
R3c+3usaloBspCJEsV/zcmr8/ydX31lug3CGw90WtLfFWjurZcFuG/gvFfF/kYJU
NTS/VZmQeF6ZMiUa1ls7BMI=
-----END PRIVATE KEY-----
"""

_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+5yyxYhCPpx7QT8LmVO7
gy2OxDfl5u7wRxPITwC+4JwmFTKJkps3u/1H81apDs+okH+1gfrbDrafxQ3fopRL
3tNXtIePWzXC2/j+36Lmo0Bj/a9J5MX+TU/gT5JKTW2SITva3TrmI+V20R/yeEhJ
6NiruDkBB+szUQ4fL+ewMlnOZ7b79/ThVIgUOPlmlq0NAxo9AJJJehaVRmXCpW9V
s8OJhTKfRqaL3xnKbLib2qxtaU2pNbUblGjWtvT/J5vMBsxIw04DrzmsZZYpN81R
hInGhWm+y+dxwsLke212U19BvsNszYpapSIzzsfz39XbrKH5mMqkmtH6OvRzgTX7
mQIDAQAB
-----END PUBLIC KEY-----
"""

_csr = """-----BEGIN CERTIFICATE REQUEST-----
MIIC1jCCAcACAQAwaDFmMBYGA1UEBgwPW29iamVjdCBPYmplY3RdMBwGCSqGSIb3
DQEJAQwPW29iamVjdCBPYmplY3RdMAkGA1UEBgwCQ1owCwYDVQQHDARCcm5vMBYG
A1UECgwPW29iamVjdCBPYmplY3RdMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA+5yyxYhCPpx7QT8LmVO7gy2OxDfl5u7wRxPITwC+4JwmFTKJkps3u/1H
81apDs+okH+1gfrbDrafxQ3fopRL3tNXtIePWzXC2/j+36Lmo0Bj/a9J5MX+TU/g
T5JKTW2SITva3TrmI+V20R/yeEhJ6NiruDkBB+szUQ4fL+ewMlnOZ7b79/ThVIgU
OPlmlq0NAxo9AJJJehaVRmXCpW9Vs8OJhTKfRqaL3xnKbLib2qxtaU2pNbUblGjW
tvT/J5vMBsxIw04DrzmsZZYpN81RhInGhWm+y+dxwsLke212U19BvsNszYpapSIz
zsfz39XbrKH5mMqkmtH6OvRzgTX7mQIDAQABoCswKQYJKoZIhvcNAQkOMRwwGjAY
BgNVHREEEQwPW29iamVjdCBPYmplY3RdMAsGCSqGSIb3DQEBCwOCAQEABc3uMpBl
4pzEWompewTS4qWBHfBXw/7KrZNkPp91DWui11JJ3LpOTf9UgC0yxfAMXSQ/t8Md
lELq7irhH26Q4tDGJM+651UvF6hTg+lJH15Blr5H3Bemq1f4dQF9THjcnBWXaslx
gVQ/qVkHlkbYHqvxRNMU2tXIGxkZ+zQVFuZPJ2FgOOC+C+/NCNc9yOCeSFCUJzIt
NZFkI/cx9JW45a8To02kPRd9+P6GhAPOkdYk4vdAmQBOA3Z/jF2KjFs47iKwFhMF
1s8ntx0U5m80yqo3E/qf6YCl6h4ASmHXwBwx0brmAlNI3v667IctTd2RYQVwuWEK
avQMJx0EERgl5w==
-----END CERTIFICATE REQUEST-----
"""


class TestInvitation(TestCase):
    @classmethod
    def setUpTestData(cls):
        """Prepare data for manipulation in test cases.

            1. Create new organization.
            2. Create users with, resp. without admin rights.
            3. Create UserRoles in the system.
        """
        # super(TestInvitation, cls).setUpClass()
        cls.client = Client()
        cls.org = Organization.objects.create(
            name="My Organization 1",
            email="admin@myorg1.com",
            phone="887555473",
            address="Hawai, Janosikova 4",
            created=datetime.now())
        cls.org.save()
        cls.admin_user = User.objects.create_user(
            name="Admin User",
            email="admin@site.com",
            password="adminadmin",
            phone="123456789",
            address="Admin City")
        cls.admin_role = UserRole.objects.create(
            user=cls.admin_user,
            organization=cls.org,
            superuser=True)
        # default_file_permissions=31)
        cls.regular_user = User.objects.create_user(
            name="Regular User",
            email="regular@site.com",
            password="regular",
            phone="123456789",
            address="Regular City")
        cls.regular_role = UserRole.objects.create(
            user=cls.regular_user,
            organization=cls.org,
            superuser=False)
        # default_file_permissions=31)
        cls.admin_role.save()
        cls.regular_role.save()
        # Retireve created users
        cls.initial_users = User.objects.filter().count()
        cls.initial_org = Organization.objects.filter().count()
        cls.initial_roles = UserRole.objects.filter().count()

    def test_organization_created(self):
        """Test that all objects were created succesfully."""
        self.assertEqual(self.initial_org, 1)

    def test_users_created(self):
        """Test that all objects were created succesfully."""
        self.assertEqual(self.initial_users, 2)

    def test_roles_created(self):
        """Test that all objects were created succesfully."""
        self.assertEqual(self.initial_roles, 2)

    def test_guest_redirected(self):
        """That regular user was redirected when attempting to access invite"""
        response = self.client.get('/invite/')
        self.assertEqual(response.status_code, 302)

    def test_regular_user_redirected(self):
        """That regular user was redirected when attempting to access invite"""
        self.client.login(username=self.regular_user.email, password="regular")
        response = self.client.get('/invite/')
        self.client.logout()
        self.assertEqual(response.status_code, 302)

    def test_admin_get(self):
        """That regular user was redirected when attempting to access invite"""
        self.client.login(
            username=self.admin_user.email, password="adminadmin")
        response = self.client.get('/invite/')
        self.client.logout()
        self.assertEqual(response.status_code, 200)

    def test_admin_post(self):
        """Test that invitation was created succesfully."""
        post_data = {
            'organizations': self.org.id,
            'user_name': 'Invited User',
            'email': 'ivited@org.com',
            'phone': '000000001',
            'superuser': False,
            'can_invite': False,
            'can_view': False,
            'can_comment': False,
            'can_modify': False,
            'can_sign': False,
            'can_remove': False,
            # 'permissions': permissions._permissions
        }
        self.client.login(username=self.admin_user.email,
                          password="adminadmin")
        response = self.client.post('/invite/', post_data)
        print(response)
        self.client.logout()
        inv_count = Invitation.objects.filter(email=post_data['email']).count()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(inv_count, 1)

    def test_duplicate_invitation(self):
        post_data = {
            'organizations': self.org.id,
            'user_name': 'Duplicated User',
            'email': 'ivited@org.com',
            'phone': '000000001',
            'superuser': False,
            'can_invite': False,
            # 'permissions': permissions._permissions
        }
        self.client.login(username=self.admin_user.email,
                          password="adminadmin")
        self.client.post('/invite/', post_data)
        with self.assertRaises(exceptions.InvitationExistsException):
            self.client.post('/invite/', post_data)
        self.client.logout()

    def test_duplicate_user(self):
        post_data = {
            'organizations': self.org.id,
            'user_name': 'Duplicated User',
            'email': 'regular@site.com',
            'phone': '000000001',
            'superuser': False,
            'can_invite': False,
            # 'permissions': permissions._permissions
        }
        self.client.login(username=self.admin_user.email,
                          password="adminadmin")
        with self.assertRaises(exceptions.UserExistsException):
            self.client.post('/invite/', post_data)
        self.client.logout()


class TestRegister(TestCase):
    """Test registration of new user.

    This test case explores that it is possible to:
        1. Access web page from invitation.
        2. Post valid data to registration page.
        3. New user is created in the system.
        4. Certificate was generated for a user.
        5. User can log in to the system.
    """

    @classmethod
    def setUpTestData(cls):
        """Prepare data fro test cases.

            1. Create new organization.
            2. Create invitation.
        """
        cls.client = Client()
        cls.org = Organization.objects.create(
            name="My Organization 1",
            email="admin@myorg1.com",
            phone="887555473",
            address="Hawai, Janosikova 4",
            created=datetime.now())
        cls.org.save()
        cls.inv = Invitation.objects.create(
            reg_uuid=str(uuid4()).replace('-', ''),
            user_name='Invited User',
            email='invited@org.com',
            phone='1230000',
            organization=cls.org,
            superuser=False,
            # default_file_permissions=1,
            can_invite=True,
            expiration=datetime.now()+timedelta(days=1),
            secret_code=str(uuid4())[:5])
        cls.inv.save()
        signer = Signer()
        register_data = {
            'signature': signer.sign(cls.inv.reg_uuid),
            'user_name': cls.inv.user_name,
            'email': cls.inv.email,
            'login_pwd': 'password',
            'c_login_pwd': 'password',
            'key_pwd': 'password',
            'c_key_pwd': 'password',
            'phone': cls.inv.phone,
            'address': 'Janosikova 4, Hawai',
            'pub_key': _public_key,
            'priv_key': _private_key,
            'organization': 'someorg',
            'superuser': cls.inv.superuser,
            'can_invite': cls.inv.can_invite,
            'can_view': cls.inv.can_view,
            'can_comment': cls.inv.can_comment,
            'can_sign': cls.inv.can_sign,
            'can_modify': cls.inv.can_modify,
            'can_remove': cls.inv.can_remove,
            # 'default_file_permissions': permissions._permissions,
            'csr': _csr,
        }
        cls.get_access_response = cls.client.get(
            '/register/{}/'.format(cls.inv.reg_uuid))
        cls.invalid_code_response = cls.client.post(
            '/register/{}/'.format(cls.inv.reg_uuid),
            {'secret_code': '0000'})
        cls.valid_code_response = cls.client.post(
            '/register/{}/'.format(cls.inv.reg_uuid),
            {'secret_code': cls.inv.secret_code})
        cls.register_response = cls.client.post(
            '/register/submit/', register_data)

    def test_reg_access_get(self):
        """Test that we can access code enter page."""
        self.assertEqual(self.get_access_response.status_code, 200)

    def test_invalid_code_entered(self):
        """Test that when invalid code entered user can not access."""
        self.assertEqual(self.invalid_code_response.status_code, 404)

    def test_valid_code_entered(self):
        """Test that when correct code entered user can access registration.
        """
        self.assertEqual(self.valid_code_response.status_code, 200)

    def test_post_valid(self):
        """Test correct status code returned when posting registration data."""
        self.assertEqual(self.register_response.status_code, 200)

    def test_user_created(self):
        """Test that user was sucesfully created in the system."""
        new_user = User.objects.filter(email=self.inv.email)
        self.assertEqual(len(new_user), 1)

    def test_user_role_created(self):
        new_role = UserRole.objects.filter()
        self.assertEqual(len(new_role), 1)

    def test_user_role_created(self):
        new_certificate = Certificate.objects.filter()
        self.assertEqual(len(new_certificate), 1)

    def test_asert_invitation_deleted(self):
        invitations = Invitation.objects.filter()
        self.assertEqual(len(invitations), 0)


class TestCrypto(unittest.TestCase):
    """Test cryptographic function implemented on server side."""

    @classmethod
    def setUpclass(cls):
        pass

    # TODO: add more thorough test case
    def test_create_certificate(self):
        """Test that we can generate certificate from valid CSR."""
        cert = crypto.CertificateHandler.generate_new(_csr)
        self.assertNotEqual(cert, None)
