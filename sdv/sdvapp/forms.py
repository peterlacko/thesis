# ===================
# author: Peter Lacko
# year: 2016
# ===================

from django import forms
from django.core.validators import RegexValidator
from .models import Organization


class InvitationForm(forms.Form):
    organizations = forms.ChoiceField(
        label='Add to organization', choices=())
    user_name = forms.CharField(label='User\'s full name', max_length=255)
    email = forms.EmailField(label='Email address', max_length=255)
    phone = forms.CharField(label='Mobile number', max_length=255)
    superuser = forms.BooleanField(label='Is Administrator', required=False)
    can_invite = forms.BooleanField(label='Can invite', required=False)
    can_view = forms.BooleanField(label='Can view', required=False)
    can_comment = forms.BooleanField(label='Can comment', required=False)
    can_sign = forms.BooleanField(label='Can sign', required=False)
    can_modify = forms.BooleanField(label='Can modify', required=False)
    can_remove = forms.BooleanField(label='Can remove', required=False)

    def __init__(self, *args, **kwargs):
        organizations = kwargs.pop('organizations')
        super(InvitationForm, self).__init__(*args, **kwargs)
        if organizations is not None:
            org_choices = ((org.id, org.name) for org in organizations)
            self.fields['organizations'].choices = org_choices


class AccessRegistrationForm(forms.Form):
    secret_code = forms.CharField(widget=forms.PasswordInput, max_length=5)


class RegistrationForm(forms.Form):
    organization = forms.CharField(
        label='Organization', max_length=255, disabled=True, required=False)
    user_name = forms.CharField(
        label='User\'s full name', max_length=255,
        disabled=True, required=False)
    email = forms.EmailField(label='Email address', max_length=255, disabled=True, required=False)
    phone = forms.CharField(label='Mobile number', max_length=255, disabled=True, required=False)
    superuser = forms.BooleanField(
        label='Administrator', required=False, disabled=True)
    can_invite = forms.BooleanField(label='Can invite', required=False, disabled=True)
    can_view = forms.BooleanField(label='Can view', required=False, disabled=True)
    can_comment = forms.BooleanField(label='Can comment', required=False, disabled=True)
    can_sign = forms.BooleanField(label='Can sign', required=False, disabled=True)
    can_modify = forms.BooleanField(label='Can modify', required=False, disabled=True)
    can_remove = forms.BooleanField(label='Can remove', required=False, disabled=True)
    address = forms.CharField(label='Your address', max_length=255)
    login_pwd = forms.CharField(
        label="Login password", max_length=32,
        widget=forms.PasswordInput, required=True,
        initial='admin')
    c_login_pwd = forms.CharField(
        label="Confirm login password", max_length=32,
        widget=forms.PasswordInput, required=True,
        initial='admin')
    key_pwd = forms.CharField(
        label="Key password", max_length=32,
        widget=forms.PasswordInput, required=True,
        initial='admin')
    c_key_pwd = forms.CharField(
        label="Confirm key password", max_length=32,
        widget=forms.PasswordInput, required=True,
        initial='admin')
    signature = forms.CharField(widget=forms.HiddenInput(), required=True)
    priv_key = forms.CharField(widget=forms.HiddenInput(), required=True, initial='')
    pub_key = forms.CharField(widget=forms.HiddenInput(), required=True, initial='')
    csr = forms.CharField(widget=forms.HiddenInput(), required=True, initial='')

    def __init__(self, *args, **kwargs):
        try:
            reg_data = kwargs.pop('inv_data')
        except KeyError:  # form is bound
            super(RegistrationForm, self).__init__(*args, **kwargs)
            return
        super(RegistrationForm, self).__init__(*args, **kwargs)
        self.fields['organization'].initial = (
            Organization.objects.get(
                id=reg_data['organization_id']).name)
        self.fields['user_name'].initial = reg_data['user_name']
        self.fields['email'].initial = reg_data['email']
        self.fields['phone'].initial = reg_data['phone']
        self.fields['superuser'].initial = reg_data['superuser']
        self.fields['can_invite'].initial = reg_data['can_invite']
        self.fields['can_view'].initial = reg_data['can_view']
        self.fields['can_comment'].initial = reg_data['can_comment']
        self.fields['can_sign'].initial = reg_data['can_sign']
        self.fields['can_modify'].initial = reg_data['can_modify']
        self.fields['can_remove'].initial = reg_data['can_remove']
        self.fields['signature'].initial = reg_data['signature']


class NewFileUploadForm(forms.Form):
    """Handles uploading of new file to the server."""
    organizations = forms.ChoiceField(label='Add to organization', choices=())
    due_date = forms.DateTimeField(widget=forms.DateTimeInput())
    filefield = forms.FileField(label='Select document')

    def __init__(self, *args, **kwargs):
        organizations = kwargs.pop('organizations')
        super(NewFileUploadForm, self).__init__(*args, **kwargs)
        if organizations is not None:
            org_choices = ((org.id, org.name) for org in organizations)
            self.fields['organizations'].choices = org_choices


class NewVersionUploadForm(forms.Form):
    """Handles uploading of new version of file to the server."""
    current_version = forms.CharField(required=True, initial='', disabled=True)
    document_name = forms.CharField(required=True, initial='', disabled=True)
    filefield = forms.FileField(label='Select document')

    def __init__(self, *args, **kwargs):
        version = kwargs.pop('version')
        name = kwargs.pop('name')
        super(NewVersionUploadForm, self).__init__(*args, **kwargs)
        self.fields['current_version'].initial = version
        self.fields['document_name'].initial = name
