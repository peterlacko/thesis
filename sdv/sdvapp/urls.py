# ===================
# author: Peter Lacko
# year: 2016
# ===================

from django.conf.urls import url
from django.contrib.auth import views as auth_views

from . import views

app_name = 'sdvapp'
urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^home/$', views.HomeView.as_view(), name='home'),
    url(r'^login/', auth_views.login, {'template_name': 'sdvapp/login.html'}, name='login'),
    url(r'^logout/',
        auth_views.logout,
        {'template_name': 'sdvapp/logout.html'},
        name='logout'),
    url(r'^invite/', views.CreateInvitation.as_view(), name='invitation'),
    url(r'^register/submit/',
        views.RegistrationSubmitView.as_view(),
        name='registration_submit'),
    url(r'^register/(?P<invitation_id>[0-9a-zA-Z]{32})/',
        views.RegistrationView.as_view(),
        name='registration_access'),
    url(r'^profile/', views.ProfileView.as_view(), name='profile'),
    # get requests here
    url(r'^resources/get/privkey/',
        views.PrivateKeyHandler.as_view(),
        name='res_get_privkey'),
    url(r'^resources/get/certificate/',
        views.CertificateHandler.as_view(),
        name='res_get_certificate'),
    url(r'^resources/newdocumentuploadform/$',
        views.NewFileUploadForm.as_view(),
        name='res_newfileuploadform'),
    url(r'^resources/get/newversionuploadform/$',
        views.NewVersionUploadForm.as_view(),
        name='res_newversionuploadform'),
    url(r'^resources/organization/certificates/.*$',
        views.OrganizationCertificates.as_view(),
        name='res_organization_certificates'),
    url(r'^resources/organization/signators/.*$',
        views.OrganizationSignators.as_view(),
        name='res_organization_signators'),
    url(r'^resources/document/details/.*$',
        views.DocumentDetails.as_view(),
        name='res_get_document_details'),
    url(r'^resources/document/signaturesbatch/.*$',
        views.DocumentSignaturesBatch.as_view(),
        name='res_document_signatures_batch'),
    url(r'^resources/documentversion/details/.*$',
        views.DocumentVersionDetails.as_view(),
        name='res_documentversion_details'),
    url(r'^resources/documentversion/signaturesbatch/.*$',
        views.DocumentVersionSignaturesBatch.as_view(),
        name='res_document_version_signatures_batch'),
    url(r'^resources/get/ddd/.*$',
        views.DocumentDecryptionData.as_view(),
        name='res_get_ddd'),
    url(r'^resources/document/version/$',
        views.DocumentVersionHandler.as_view(),
        name='res_documentversion'),
    url(r'^resources/document/history/$',
        views.DocumentCollaboration.as_view(),
        name='res_documentcollaboration'),
    url(r'^resources/document/signature/$',
        views.DocumentVersionSignature.as_view(),
        name='res_post_signature'),
    url(r'^resources/document/$',
        views.DocumentHandler.as_view(),
        name='res_document'),
]
