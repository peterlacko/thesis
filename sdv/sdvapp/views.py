# ===================
# author: Peter Lacko
# year: 2016
# ===================

# Django views file
import json
from datetime import datetime, timedelta
from uuid import uuid4
from urllib.parse import urlsplit, urlunsplit

from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import render

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
# from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.core.signing import Signer
from django.db import transaction
from django.db import IntegrityError
from django.db.models import Q, Max

from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.views.decorators.http import require_safe, require_POST
from django.views.generic import ListView
from django.views.generic.base import TemplateView

from .exceptions import (
    InvitationExistsException,
    UserExistsException,
)
from .models import (
    Certificate,
    DocumentContainer,
    DocumentVersion,
    Invitation,
    Organization,
    Signator,
    Signature,
    User,
    UserDocumentPermissions,
    UserRole,
)
from .forms import (
    AccessRegistrationForm,
    InvitationForm,
    NewFileUploadForm,
    NewVersionUploadForm,
    RegistrationForm,
)
from .utils.crypto import MyCertificateHandler


class IndexView(TemplateView):
    template_name = 'sdvapp/index.html'


class HomeView(LoginRequiredMixin, TemplateView):
    """Default view for user after login. """
    http_method_names = ['get']
    docs_template = 'sdvapp/user/home.html'

    def get(self, request, *args, **kwargs):
        """Handle all get requests on 'home' view."""
        files = DocumentContainer.objects.filter(
            document_permissions_set__user=request.user,
            document_permissions_set__can_view=True).distinct()
        return render(request, self.docs_template, {'documents': files})


class CreateInvitation(LoginRequiredMixin, UserPassesTestMixin, TemplateView):
    http_method_names = ['get', 'post']
    invitation_template = 'sdvapp/invitation/invite.html'
    invited_template = 'sdvapp/invitation/confirmed.html'
    form_class = InvitationForm
    organizations_admin = []
    uuid = None
    secret_code = None

    # if this is a POST request we need to process the form data
    def post(self, request, *args, **kwargs):
        form = self.form_class(
            request.POST,
            organizations=self.organizations_admin)
        if form.is_valid():
            self.process_form(form)
            url_parsed = urlsplit(request.build_absolute_uri())
            path = reverse(
                'sdvapp:registration_access',
                current_app=self.request.resolver_match.namespace,
                args=(self.uuid,))
            url = urlunsplit((url_parsed.scheme, url_parsed.netloc, path, '', ''))
            return render(
                request, self.invited_template,
                {
                    'url': url,
                    'secret_code': self.secret_code
                })
        return render(request, self.invitation_template, {'form': form})

    # if a GET (or any other method) we'll create a blank form
    def get(self, request, *args, **kwargs):
        form = self.form_class(organizations=self.organizations_admin)
        return render(request, self.invitation_template, {'form': form})

    def test_func(self):
        self.organizations_admin = list(Organization.objects.filter(
            user__email=self.request.user.email,
            userrole__superuser=True,
        ))
        if not self.organizations_admin:
            return False
        return True

    def process_form(self, form):
        organization = form.cleaned_data['organizations']
        user_name = form.cleaned_data['user_name']
        email = form.cleaned_data['email']
        phone = form.cleaned_data['phone']
        superuser = form.cleaned_data['superuser']
        can_invite = form.cleaned_data['can_invite']
        can_view = form.cleaned_data['can_view']
        can_comment = form.cleaned_data['can_comment']
        can_sign = form.cleaned_data['can_sign']
        can_modify = form.cleaned_data['can_modify']
        can_remove = form.cleaned_data['can_remove']
        # permissions = form.cleaned_data['default_file_permissions']

        # custom generated values
        reg_uuid = str(uuid4()).replace('-', '')
        expiration = datetime.now() + timedelta(days=1)
        secret_code = str(uuid4())[:5]

        # Check if user with given name or phone already exists.
        user_exists = User.objects.filter(Q(email=email) | Q(phone=phone))
        if user_exists:
            raise UserExistsException
        invitation_exists = Invitation.objects.filter(
            Q(email=email) | Q(phone=phone))
        if invitation_exists:
            raise InvitationExistsException

        inv = Invitation(
            reg_uuid=reg_uuid,
            user_name=user_name,
            email=email,
            phone=phone,
            organization=Organization.objects.get(id=organization),
            superuser=superuser,
            can_invite=can_invite,
            can_view=can_view,
            can_comment=can_comment,
            can_modify=can_modify,
            can_sign=can_sign,
            can_remove=can_remove,
            expiration=expiration,
            secret_code=secret_code)
        inv.save()
        self.uuid = reg_uuid
        self.secret_code = secret_code


class RegistrationView(TemplateView):
    """Class for accessing Registration view"""
    http_method_names = ['get', 'post']
    access_template = "sdvapp/registration/access.html"
    registration_template = "sdvapp/registration/register.html"
    access_form_class = AccessRegistrationForm
    registration_form_class = RegistrationForm

    def get(self, request, *args, **kwargs):
        access_form = self.access_form_class()
        invitation_id = kwargs.pop('invitation_id')
        if Invitation.objects.get(reg_uuid=invitation_id) is None:
            return HttpResponseNotFound()
        return render(
            request, self.access_template,
            {
                'form': access_form,
                'access_url': '/register/{}/'.format(invitation_id)
            })

    def post(self, request, *args, **kwargs):
        invitation_id = kwargs.pop('invitation_id')
        access_form = self.access_form_class(request.POST)
        if access_form.is_valid():
            if not self.check_secret_code(access_form, invitation_id):
                return render(
                    request, self.access_template,
                    {'form': access_form, 'wrong_code': True}, status=404)
            inv_data = Invitation.objects.filter(reg_uuid=invitation_id).values()[0]
            signer = Signer()
            signature = signer.sign(invitation_id)
            inv_data['signature'] = signature
            registration_form = self.registration_form_class(inv_data=inv_data)
            return render(
                request, self.registration_template,
                {'form': registration_form})

        return render(
            request, self.access_template,
            {'form': access_form})

    def check_secret_code(self, form, invitation_id):
        inv = Invitation.objects.get(reg_uuid=invitation_id)
        if not inv:
            raise HttpResponseNotFound()
        if inv.secret_code != form.cleaned_data['secret_code']:
            return False
        return True


class RegistrationSubmitView(TemplateView):
    """Handle last step in user registration."""
    http_method_names = ['post']
    registration_form_class = RegistrationForm
    registration_submit_template = "sdvapp/registration/submit.html"

    def post(self, request, *args, **kwargs):
        reg_form = self.registration_form_class(request.POST)
        if reg_form.is_valid():
            # Raise an exception if signature is broken
            signer = Signer()
            invitation_id = signer.unsign(reg_form.cleaned_data['signature'])
            self.process_form(reg_form, invitation_id)
            # Delete invitation
            Invitation.objects.filter(reg_uuid=invitation_id).delete()
            return render(request, self.registration_submit_template)
        else:
            raise ValidationError("Form Validation Error", code='validate')

    def process_form(self, form, invitation_id):
        inv_data = Invitation.objects.get(reg_uuid=invitation_id)
        # create user object
        user = User.objects.create_user(
            name=inv_data.user_name,
            email=inv_data.email,
            password=form.cleaned_data['login_pwd'],
            phone=inv_data.phone,
            address=form.cleaned_data['address'])

        user.pubkey = form.cleaned_data['pub_key']
        user.privkey = form.cleaned_data['priv_key']

        # create role for user
        user_role = UserRole(
            user=user,
            organization=inv_data.organization,
            superuser=inv_data.superuser,
            can_invite=inv_data.can_invite,
            can_view=inv_data.can_view,
            can_comment=inv_data.can_comment,
            can_modify=inv_data.can_modify,
            can_sign=inv_data.can_sign,
            can_remove=inv_data.can_remove,
        )

        # generate certificate for user
        my_cert = MyCertificateHandler.generate_new(form.cleaned_data['csr'])
        cert = Certificate(certificate=my_cert, valid=True, owner=user)
        user.save()
        user_role.save()
        cert.save()


class ProfileView(LoginRequiredMixin, TemplateView):
    """Handles user's configuration."""
    template = "sdvapp/user/profile.html"
    http_method_names = ['get', 'post']

    def get(self, request, *args, **kwargs):
        roles = UserRole.objects.filter(user=request.user)
        return render(request, self.template, {'roles': roles})


# ****************************************************************************
# Views for rendering content to templates asynchronously
# ****************************************************************************
class DocumentDetails(LoginRequiredMixin, TemplateView):
    http_method_names = ['get']
    template = "sdvapp/documents/documentdetails.html"

    def get(self, request):
        """Returns details about requested document."""
        try:
            document_id = request.GET.get('document_id')
            if not request.user.can_view(document_id):
                return HttpResponseForbidden("You don't have permissions to access this document")
            dc = DocumentContainer.objects.get(id=document_id)
            return render(request, self.template, {'document': dc})
        except KeyError:
            return HttpResponseBadRequest("Incorrect parameters!")


class DocumentVersionDetails(LoginRequiredMixin, TemplateView):
    http_method_names = ['get']
    template = "sdvapp/documents/documentversiondetails.html"

    def get(self, request):
        """Returns details about specific version of document."""
        try:
            document_id = request.GET.get('document_id')
            version = request.GET.get('version')
            if not request.user.can_view(document_id):
                return HttpResponseForbidden("You don't have permissions to access this document")
            dv = DocumentVersion.objects.get(document=document_id, version=version)
            return render(request, self.template, {'document': dv})
        except KeyError:
            return HttpResponseBadRequest("Incorrect parameters!")


class NewFileUploadForm(LoginRequiredMixin, TemplateView):
    """Request form for uploading new file."""
    http_method_names = ['get']
    newfileupload_template = 'sdvapp/documents/newfileupload.html'
    newfileupload_form = NewFileUploadForm

    def get(self, request, *args, **kwargs):
        """Request form for uploading new file."""
        organizations = Organization.objects.filter(
            userrole__user=request.user,
            userrole__can_modify=True)
        form = self.newfileupload_form(organizations=organizations)
        return render(request, self.newfileupload_template, {'form': form})


class NewVersionUploadForm(LoginRequiredMixin, TemplateView):
    http_method_names = ['get']
    newversionupload_template = 'sdvapp/documents/newversionupload.html'
    newversionupload_form = NewVersionUploadForm

    def get(self, request):
        """Request form for uploading new version of docuemnt."""
        # get document id first from request
        document_id = int(request.GET.get('document_id'))
        current_version = DocumentContainer.objects.get(id=document_id).current_version().version
        name = DocumentContainer.objects.get(id=document_id).name
        form = self.newversionupload_form(version=current_version, name=name)
        return render(request, self.newversionupload_template, {'form': form})


# ************************************************************************
# ************************************************************************
#
# RESOURCES
#
# Set of methods for providing access to Common Server Resources.
# Example of such resource is list of users of certain organization,
# list of files of given user, or more complex data which can be requested
# from any page within application.
#
# ************************************************************************
# ************************************************************************
class OrganizationCertificates(LoginRequiredMixin, TemplateView):
    """Return certificates of all users of certain organization."""
    http_method_names = ['get']

    def get(self, request):
        org = request.GET.get('organization')
        certificates = Certificate.objects.filter(
            owner__userrole__organization=org)
        # users = User.objects.filter(userrole__organization=org)
        # FIXME: checking for invalid keys and certificates
        certificates = {c.owner.id: c.certificate for c in certificates if c.valid is True}
        response = {
            'status': 'OK',
            'message': '',
            'data': {'certificates': certificates}
        }
        return JsonResponse(response)


class OrganizationSignators(LoginRequiredMixin, TemplateView):
    """Return certificates of all users of certain organization."""
    http_method_names = ['get']

    def get(self, request):
        org = request.GET.get('organization_id')
        users = User.objects.filter(userrole__organization=org, userrole__can_sign=True)
        signators = {u.id: u.email for u in users}
        response = {
            'status': 'OK',
            'message': '',
            'data': {'signators': signators}
        }
        return JsonResponse(response)


class PrivateKeyHandler(LoginRequiredMixin, TemplateView):
    http_method_names = ['get']

    def get(self, request):
        """Get private key of currently logged in user."""
        key = request.user.privkey
        response = {
            'status': 'OK',
            'message': '',
            'data': {
                'pkcs12key': key
            }
        }
        return JsonResponse(response)


class CertificateHandler(LoginRequiredMixin, TemplateView):
    http_method_names = ['get']

    def get(self, request):
        """Get certificate of currently logged in user, or one specified in POST."""
        cert = None
        if request.GET.get('email', None) is not None:
            user = User.objects.get(email=request.GET.get('email'))
            cert = Certificate.objects.get(owner=user.id).certificate
        elif request.GET.get('user_id', None) is not None:
            user = User.objects.get(id=int(request.GET.get('user_id')))
            cert = Certificate.objects.get(owner=user.id).certificate
        else:
            cert = Certificate.objects.get(owner=request.user.id).certificate
        response = {
            'status': 'OK',
            'message': '',
            'certificate': cert
        }
        return JsonResponse(response)


class DocumentDecryptionData(LoginRequiredMixin, TemplateView):
    http_method_names = ['get']

    def get(self, request):
        """Returns DocumentDecryptionData for requested document.

        These are iv and encryption key for document decryption.
        If version is not contained in request, iv won't be returned.
        """
        try:
            id = int(request.GET.get('document_id'))
            requested_version = request.GET.get('version', default=None)
            current_version = DocumentContainer.objects.get(id=id).current_version().version
            if requested_version is not None:
                requested_version = int(requested_version)
                if requested_version <= 0 or requested_version > current_version:
                    version = current_version
                else:
                    version = requested_version
            else:
                version = None
            if request.user.can_view(id):
                response = {}
                if version is not None:
                    iv = DocumentVersion.objects.get(
                        document=id, version=version).iv
                    response['iv'] = iv
                key = UserDocumentPermissions.objects.get(
                    user=request.user.id, document=id).document_key
                response['status'] = 'OK'
                response['message'] = ''
                response['key'] = key
                return JsonResponse(response)
            else:
                return HttpResponseForbidden(
                    "You don't have permissions to access this document")
        except KeyError:
            response = {
                'status': 'Fail',
                'message': 'Incorrect parameters.'
            }
            return JsonResponse(response, status_code=400)


class DocumentVersionSignaturesBatch(LoginRequiredMixin, TemplateView):
    http_method_names = ['get']

    def get(self, request):
        """Returns all signatures from requested document/version combination."""
        try:
            document_id = int(request.GET.get('document_id'))
            if request.user.can_view(document_id):
                requested_version = int(request.GET.get('version'))
                current_version = DocumentContainer.objects.get(
                    id=document_id).current_version().version
                if requested_version == 0:
                    requested_version = current_version
                elif requested_version < 0 or requested_version > current_version:
                    response = {
                        'status': 'Fail',
                        'message': ('Requested version does not exist ',
                                    '(current={}, requested={})').format(current, requested)
                    }
                else:
                    dv = DocumentVersion.objects.get(
                        document=document_id,
                        version=requested_version).id
                    signatures = {
                        str(s.user.email): [str(s.user), s.signature]
                        for s in Signature.objects.filter(version=dv)
                    }
                    response = {
                        'status': 'OK',
                        'message': '',
                        'data': {
                            'signatures': signatures,
                            'version': requested_version
                        }
                    }
                    return JsonResponse(response)
        except KeyError:
            response = {
                'status': 'Fail',
                'message': 'Incorrect parameters.'
            }
            return JsonResponse(response, status_code=400)


class DocumentSignaturesBatch(LoginRequiredMixin, TemplateView):
    http_method_names = ['get']

    def get(self, request):
        """Returns all signatures from requested document."""
        try:
            document_id = int(request.GET.get('document_id'))
            if request.user.can_view(document_id):
                versions = DocumentVersion.objects.filter(document=document_id)
                signatures = {}
                for v in versions:
                    signatures[str(v.version)] = {
                        str(s.user): s.signature for s in Signature.objects.filter(version=v.id)
                    }
                response = {
                    'status': 'OK',
                    'message': '',
                    'data': signatures
                }
                print(response)
                return JsonResponse(response)
            else:
                response = {
                    'status': 'Fail',
                    'message': "You don't have permissions to access this document!"
                }
                return JsonResponse(response, status_code=403)
        except KeyError:
            response = {
                'status': 'Fail',
                'message': 'Incorrect parameters.'
            }
            return JsonResponse(response, status_code=400)


class DocumentVersionSignature(LoginRequiredMixin, TemplateView):
    """Handle single signature over document version."""
    http_method_names = ['post']

    @transaction.atomic
    def post(self, request):
        """Save signature to specified document/version/user/time combination."""
        try:
            document_id = int(request.POST.get('document_id'))
            signature = request.POST.get('signature')
            requested_version = int(request.POST.get('version'))
            current_version = DocumentContainer.objects.get(
                id=document_id).current_version().version
            if requested_version != current_version:
                response = {
                    'status': 'Fail',
                    'message': 'You are signing outdated version'
                }
                return JsonResponse(response, status_code=400)
            if not request.user.can_sign(document_id):
                response = {
                    'status': 'Fail',
                    'message': "You don't have permissions to sign this document!"
                }
                return JsonResponse(response, status_code=400)
            dv = DocumentVersion.objects.get(
                document=document_id, version=current_version)
            sig = Signature(
                user=request.user,
                version=dv,
                signature=signature,
                timestamp=datetime.now(),
            )
            # If already signed, notify user
            try:
                sig.save()
            except IntegrityError:
                return JsonResponse(
                    {
                        'status': 'Fail',
                        'message': 'You already signed this document'
                    })
            if self.check_approved(document_id):
                defaults = {'status': 'AP'}
                doc, created = DocumentContainer.objects.update_or_create(
                    id=document_id, defaults=defaults)
                if not created:
                    doc.save()
                    print('Approved and saved!')
            else:
                print('Not approved yet')
            return JsonResponse(
                {
                    'status': 'OK',
                    'message': 'Document signed succesfully',
                })
        except KeyError:
            response = {
                'status': 'Fail',
                'message': 'Incorrect parameters.'
            }
            return JsonResponse(response, status_code=400)

    def check_approved(self, document_id):
        """Check if document is approved by all mandatory signators."""
        mandatory_signators = Signator.objects.filter(document=document_id)
        man_signed = {s.user for s in mandatory_signators}
        current_version = DocumentContainer.objects.get(id=document_id).current_version()
        cv_signatures = Signature.objects.filter(version=current_version.id)
        cv_signed = {s.user for s in cv_signatures}
        if man_signed.issubset(cv_signed):
            return True
        return False


class DocumentLock(LoginRequiredMixin, TemplateView):
    """Handle locking and unlocking operations over document."""

    @transaction.atomic
    def post(self, request):
        """Document locking is available over post method."""
        response = {
            'status': 'Fail',
            'message': 'Not Implemented!'
        }
        return JsonResponse(response, status_code=501)
        try:
            document_id = int(request.POST.get('document_id'))
            if not request.user.can_modify(document_id):
                return HttpResponseForbidden("You don't have permissions to modify document")
            duration = request.POST.get('duration')
            document = DocumentContainer.objects.get(id=document_id)
            if document.lock_owner is not None:
                response = {
                    'status': 'Fail',
                    'message': 'Document already locked by {}'.format(document.lock_owner)
                }
                return JsonResponse(request, status_code=403)
        except KeyError:
            return HttpResponseBadRequest("Incorrect parameters!")

    def get(self, request):
        """Get status of lock on current document."""
        """Document locking is available over post method."""
        response = {
            'status': 'Fail',
            'message': 'Not Implemented!'
        }
        return JsonResponse(response, status_code=501)

    def delete(self, request):
        """Remove lock from current document, if exists."""
        response = {
            'status': 'Fail',
            'message': 'Not Implemented!'
        }
        return JsonResponse(response, status_code=501)


class DocumentCollaboration(LoginRequiredMixin, TemplateView):
    """Returns formatted document history."""
    http_method_names = ['get']
    template = "sdvapp/documents/collaborationhistory.html"

    def get(self, request):
        """Return document collaboration history formatted as an html table."""
        document_id = request.GET.get('document_id')
        if not request.user.can_view(document_id):
            response = {
                'status': 'Fail',
                'message': "You don't have permissions to review this document's history."
            }
            return JsonResponse(response, status_code=403)
        document = DocumentContainer.objects.get(id=document_id)
        versions = DocumentVersion.objects.filter(document=document_id)
        mandatory_signators = Signator.objects.filter(document=document_id)
        ms_list = [ms.user for ms in mandatory_signators]
        signed_ms = {}
        unsigned_ms = {}
        others = {}
        for v in versions:
            signed_ms[v.version] = [s.user for s in v.signature_set.filter(user__in=ms_list)]
            others[v.version] = [s.user for s in v.signature_set.exclude(user__in=ms_list)]
            unsigned_ms[v.version] = list(set(ms_list) - set(signed_ms[v.version]))
        context = {
            'document': document,
            'versions': versions,
            'mandatory_signators': mandatory_signators,
            'signed_ms': signed_ms,
            'unsigned_ms': unsigned_ms,
            'others': others
        }
        return render(request, self.template, context)


class DocumentHandler(LoginRequiredMixin, TemplateView):
    """Handler for document."""
    http_method_names = ['get', 'post', 'delete']

    @transaction.atomic
    def post(self, request):
        """Process new file from the user."""
        org_id = request.POST.pop('organization')[0]
        iv = request.POST.pop('iv')[0]
        # data = request.FILES['data']
        data = request.POST.pop('data')[0]  # <----
        name = request.POST.pop('name')[0]  # <----
        size = request.POST.pop('size')[0]  # <----
        binary = request.POST.pop('binary')[0]
        signators = json.loads(request.POST.pop('signators')[0])
        if not request.user.can_add_new(org_id):
            return HttpResponseForbidden("You don't have permissions to add new document")
        # now we can add new document and it's first version
        dc = DocumentContainer(
            organization=Organization.objects.get(id=org_id),
            # name=data.name,
            name=name  # <-----
        )
        dc.save()
        dv = DocumentVersion(
            document=dc,
            user=request.user,
            # storage_path=data,
            base64=data,  # <-----
            iv=iv,
            version=1,
            binary=binary,
            # size=data.size,
            size=size  # <----
        )
        dv.save()
        keys = json.loads(request.POST.pop('keys')[0])
        # only users left now, we will dismiss everything else
        for key, value in keys.items():
            udp = UserDocumentPermissions(
                user=User.objects.get(id=int(key)),
                document=dc,
                document_key=value,
                can_view=UserRole.objects.get(
                    user=key, organization=org_id).can_view,
                can_comment=UserRole.objects.get(
                    user=key, organization=org_id).can_comment,
                can_sign=UserRole.objects.get(
                    user=key, organization=org_id).can_sign,
                can_modify=UserRole.objects.get(
                    user=key, organization=org_id).can_modify,
                can_remove=UserRole.objects.get(
                    user=key, organization=org_id).can_remove,
            )
            udp.save()
        # check that correct signators are being added and add then
        for signator in signators:
            user = User.objects.get(id=int(signator))
            if not UserRole.objects.get(user=user, organization=org_id).can_sign:
                response = {
                    'status': 'Fail',
                    'message': 'Invalid signator specified!'
                }
                return JsonResponse(response, status_code=400)
            else:
                sig = Signator(user=user, document=dc)
                sig.save()
        response = {
            'status': 'OK',
            'message': '',
            'data': {
                'document_id': dc.id,
                'name': dc.name,
                'document_status': dc.status,
                'version': 1,
                'size': dv.size,
                'owner': dv.user.email,
            }
        }
        return JsonResponse(response)

    @transaction.atomic
    def delete(self, request):
        """Delete document from the server with all its associations."""
        try:
            document_id = int(request.DELETE.get('document_id'))
            if not request.user.can_remove(document_id):
                return HttpResponseForbidden(
                    "You don't have permissions remove this document")
            # first get relevant document versions and signatures
            signatures = Signature.objects.filter(version__document=document_id)
            dversions = DocumentVersion.objects.filter(document=document_id)
            udpermissions = UserDocumentPermissions.objects.filter(document=document_id)
            document = DocumentContainer.objects.get(id=document_id)
            signators = Signator.objects.filter(document=document_id)
            signatures.delete()
            udpermissions.delete()
            dversions.delete()
            document.delete()
            signators.delete()
            response = {
                'status': 'OK',
                'message': 'Document deleted succesfully!'
            }
            return JsonResponse(response)
        except KeyError:
            response = {
                'status': 'Fail',
                'message': 'Incorrect parameters.'
            }
            return JsonResponse(response, status_code=400)


class DocumentVersionHandler(LoginRequiredMixin, TemplateView):
    """Handle operations over custom document version."""
    http_method_names = ['get', 'post']

    def get(self, request):
        """Returns requested encrypted document after user passes test."""
        try:
            id = int(request.GET.get('document_id'))
            current_version = DocumentContainer.objects.get(id=id).current_version().version
            requested_version = int(request.GET.get('version'))
            if requested_version == 0:
                version = current_version
            elif requested_version > current_version or requested_version < 0:
                response = {
                    'status': 'Fail',
                    'message': ('Requested version does not exists '
                                '(current={}, requested={})').format(
                                    current_version, requested_version)
                }
                return JsonResponse(response, status_code=404)
            else:
                version = requested_version
            if request.user.can_view(id):
                data = DocumentVersion.objects.get(document=id, version=version).base64
                binary = DocumentVersion.objects.get(document=id, version=version).binary
                response = {
                    'status': 'OK',
                    'message': '',
                    'data': {
                        'document': data,
                        'binary': binary,
                    }
                }
                return JsonResponse(response)
            else:
                response = {
                    'status': 'Fail',
                    'message': "You don't have permissions to access this document",
                }
                return JsonResponse(response, status_code=403)
        except KeyError:
            response = {
                'status': 'Fail',
                'message': 'Incorrect parameters.'
            }
            return JsonResponse(response, status_code=400)

    @transaction.atomic
    def post(self, request):
        """Process new file from the user."""
        try:
            document_id = int(request.POST.pop('document_id')[0])
            iv = request.POST.pop('iv')[0]
            data = request.POST.pop('data')[0]
            size = request.POST.pop('size')[0]
            binary = request.POST.pop('binary')[0]
            if not request.user.can_modify(document_id):
                response = {
                    'status': 'Fail',
                    'message': "You don't have permissions to add new document",
                }
                return JsonReponse(response, status_code=403)
            dc = DocumentContainer.objects.get(id=document_id)
            current_version = dc.current_version().version
            dv = DocumentVersion(
                document=dc,
                user=request.user,
                base64=data,
                iv=iv,
                binary=binary,
                version=current_version+1,
                size=size
            )
            dv.save()
            response = {
                'status': 'OK',
                'message': '',
                'data': {'version': dv.version, 'size': dv.size}
            }
            return JsonResponse(response)
        except IndexError:
            response = {
                'status': 'Fail',
                'message': 'Incorrect parameters.'
            }
            return JsonResponse(response, status_code=400)
