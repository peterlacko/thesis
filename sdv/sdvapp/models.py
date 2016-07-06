# ===================
# author: Peter Lacko
# year: 2016
# ===================

"""Set of models representing database model."""

from django.db import models
from django.db.models import Max
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager
)
from django.contrib.postgres.fields import DateTimeRangeField
from .utils.utils import get_file_path
from django.core.exceptions import ObjectDoesNotExist, ValidationError


class Organization(models.Model):
    name = models.CharField(
        max_length=255,
        unique=True,
        blank=False,
        verbose_name='Organization name',
    )
    email = models.EmailField(max_length=255, unique=True, blank=False, default='change@me.now')
    phone = models.CharField(max_length=255,)
    address = models.CharField(max_length=255, verbose_name='Address')
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class UserManager(BaseUserManager):

    def create_user(self, name, email, password, phone='012', address='abc'):
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
        )

        user.name = name
        user.phone = phone
        user.address = address
        user.set_password(password)
        user.is_staff = False
        user.is_active = True
        user.save(using=self._db)
        return user

    def create_superuser(self, name, email, password,
                         phone='012', address='abc'):
        user = self.create_user(
            name=name, email=email, password=password,
            phone=phone, address=address)
        user.is_admin = True
        user.is_staff = True
        user.is_active = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    """Represents single user in the system."""
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,)
    name = models.CharField(
        max_length=255, blank=False, verbose_name='Full Name')
    phone = models.CharField(max_length=255, verbose_name='Telephone number')
    address = models.CharField(max_length=255, verbose_name='Address')
    created = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Account registered')
    pubkey = models.TextField(verbose_name='Public key')
    privkey = models.TextField(verbose_name='Private key')
    organization = models.ManyToManyField(
        Organization,
        through='UserRole')
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.name

    def get_full_name(self):
        return self.name

    def get_short_name(self):
        return self.name

    def has_perm(self, perm, obj=None):
        """Does the user have a specific permission?"""
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        """Does the user have permissions to view the app `app_label`?"""
        # Simplest possible answer: Yes, always
        return True

    def can_view(self, document_id):
        """Can this user view specific document?"""
        try:
            if UserDocumentPermissions.objects.get(user=self.id, document=document_id).can_view:
                return True
            return False
        except ObjectDoesNotExist:
            return False

    def can_sign(self, document_id):
        """Can this user sign specific document?"""
        try:
            if UserDocumentPermissions.objects.get(user=self.id, document=document_id).can_sign:
                return True
            return False
        except ObjectDoesNotExist:
            return False

    def can_comment(self, document_id):
        """Can this user comment on specific document?"""
        try:
            if UserDocumentPermissions.objects.get(user=user.id, document=document_id).can_comment:
                return True
            return False
        except ObjectDoesNotExist:
            return False

    def can_modify(self, document_id):
        """Can this user modify specific document, i.e upload new version?"""
        try:
            if UserDocumentPermissions.objects.get(user=self.id, document=document_id).can_modify:
                return True
            return False
        except ObjectDoesNotExist:
            return False

    def can_remove(self, document_id):
        """Can this user view specific document?"""
        try:
            if UserDocumentPermissions.objects.get(user=self.id, document=document_id).can_remove:
                return True
            return False
        except ObjectDoesNotExist:
            return False

    def can_add_new(self, organization_id):
        """Can this user add new document to the organization workspace?"""
        try:
            if UserRole.objects.get(user=self.id, organization=organization_id).can_modify:
                return True
            return False
        except ObjectDoesNotExist:
            return False


class UserRole(models.Model):
    """This model binds user to an organization.

    Each such binding holds default user's permissions for organization.
    Permissions can be overriden locally on per-document level.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    superuser = models.BooleanField(null=False, default=False)
    can_view = models.BooleanField(null=False, default=True)
    can_comment = models.BooleanField(null=False, default=True)
    can_sign = models.BooleanField(null=False, default=True)
    can_modify = models.BooleanField(null=False, default=True)
    can_remove = models.BooleanField(null=False, default=True)
    can_invite = models.BooleanField(null=False, default=False)

    class Meta:
        unique_together = ('user', 'organization')

    def __str__(self):
        return "{org}: {user}: su={su}".format(
            org=str(self.organization),
            user=str(self.user),
            su=str(self.superuser))


class Certificate(models.Model):
    """Model holds all certificates in the system for every user."""
    certificate = models.TextField()
    valid = models.BooleanField(null=False, default=True)
    owner = models.ForeignKey(User, default=1)


class DocumentContainer(models.Model):
    """Model holds all system's documents in tree-like structure.

    Every document is uniquely identified by path and name. If name field
    is empty string, entry emulates directory function.
    """
    organization = models.ForeignKey(Organization, default=1)
    # name of the file as provided by user
    name = models.CharField(max_length=255)
    # Virtual path to the file managed by database
    # TODO: write ltree field
    path = models.CharField(null=False, max_length=255, default='/')
    description = models.TextField(null=True)
    DOC_STATUS = (
        ('IP', 'In Progress'),
        ('CA', 'Rejected'),
        ('AP', 'Approved'),
    )
    status = models.CharField(max_length=2, choices=DOC_STATUS, default='IP')
    lock_owner = models.ForeignKey(
        User, null=True, default=None, related_name='user_locks')
    lock = DateTimeRangeField(null=True)
    archived = models.BooleanField(default=False, db_index=True)
    date_archived = models.DateTimeField(null=True)
    user = models.ManyToManyField(User, through='UserDocumentPermissions')
    due_date = models.DateTimeField(auto_now_add=False, null=True)

    def __str__(self):
        return self.path + self.name

    def current_version(self):
        """Returns object representing current version of document."""
        version = DocumentVersion.objects.filter(
            document=self.id).aggregate(Max('version'))['version__max']
        return DocumentVersion.objects.get(document=self.id, version=version)


class UserDocumentPermissions(models.Model):
    """Per-document user permissions. Superior to default permissions."""
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="user_permissions_set")
    document = models.ForeignKey(
        DocumentContainer,
        on_delete=models.CASCADE,
        related_name="document_permissions_set")
    document_key = models.TextField(null=True)
    can_view = models.BooleanField(null=False, default=True)
    can_comment = models.BooleanField(null=False, default=True)
    can_sign = models.BooleanField(null=False, default=True)
    can_modify = models.BooleanField(null=False, default=True)
    can_remove = models.BooleanField(null=False, default=True)

    class Meta:
        unique_together = ('user', 'document')


class DocumentVersion(models.Model):
    document = models.ForeignKey(DocumentContainer, on_delete=models.CASCADE)
    user = models.ForeignKey(User)
    version = models.IntegerField(null=False, default=1)
    # real path to the file on filesystem
    # storage_path = models.FileField(upload_to=get_file_path, null=True)
    base64 = models.TextField(null=True)
    size = models.IntegerField(null=False, default=0)
    iv = models.TextField(null=False, blank=False, default=b'0')
    valid = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True, null=True)
    binary = models.BooleanField(default=True)

    class Meta:
        unique_together = ('document', 'version')


class Action(models.Model):
    user = models.ForeignKey(User)
    created = models.DateTimeField(auto_now_add=True)
    action = models.CharField(max_length=255, )

    def __str__(self):
        return self.action


class Signator(models.Model):
    document = models.ForeignKey(DocumentContainer, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('document', 'user')


class Comment(models.Model):
    user = models.ForeignKey(User)
    document = models.ForeignKey(DocumentContainer)
    version = models.ForeignKey(DocumentVersion)
    created = models.DateTimeField(auto_now_add=True)
    comment = models.TextField()


class Signature(models.Model):
    user = models.ForeignKey(User)
    version = models.ForeignKey(DocumentVersion)
    signature = models.TextField()
    timestamp = models.TextField()

    class Meta:
        unique_together = ('user', 'version')


class Invitation(models.Model):
    """This model holds temporary entries containing user registration info.

    After time set in 'expiration' field, entry is automatically deleted from
    table. Entry is also deleted when registration form from this address
    has been submitted.
    """
    reg_uuid = models.CharField(
        max_length=50, blank=False, null=False, unique=True
    )
    user_name = models.CharField(
        max_length=255, verbose_name='User name', default='changeme')
    email = models.EmailField(
        null=False, max_length=255, verbose_name='Email address')
    phone = models.CharField(null=False, max_length=255)
    organization = models.ForeignKey(Organization)
    superuser = models.BooleanField(null=False, default=False)
    can_invite = models.BooleanField(null=False, default=False)
    can_view = models.BooleanField(null=False, default=True)
    can_comment = models.BooleanField(null=False, default=True)
    can_sign = models.BooleanField(null=False, default=True)
    can_modify = models.BooleanField(null=False, default=True)
    can_remove = models.BooleanField(null=False, default=True)
    expiration = models.DateTimeField(auto_now_add=True)
    secret_code = models.CharField(max_length=5, default='12345')
