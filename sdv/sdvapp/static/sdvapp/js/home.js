/*
 * Author: Peter Lacko
 * Year: 2016
 */

'use strict';
var appendDocumentToTable = function appendDocumentToTable(data) {
    var row =
        `<tr>
            <td class="id">${data['document_id']}</td>
            <td class="name">${data['name']}</td>
            <td class="version">${data['version']}</td>
            <td>${data['owner']}</td>
            <td>${data['document_status']}</td>
            <td class="size">${data['size']}</td>
            </tr>`
    $("#doctable").append(row);
    return;
}

var updateDocumentInTable = function updateDocumentInTable(document_id, data) {
    /*
     * Asynchronously update info about document in table
     */
    $("#doctable tr.selected").find(".version").text(data.version);
    $("#doctable tr.selected").find(".size").text(data.size);
}

var newVersionUpload = function newVersionUpload(document_id) {
    /*
     * First get public keys of collaborators on new file
     * for simplicity we will assume all users of our organization
     * will have access to the file.
     */
    var responseData = new FormData();
    var fileReader = new FileReader();
    fileReader.onerror = function(err) {
        console.error('Could not load file: ' + err)
    }
    fileReader.onload = function(event) {
        var requestData = {
            document_id: document_id
        };
        var encryptedDocument;
        $.ajax({
            url: "/resources/get/ddd/",
            method: "GET",
            data: requestData,
            dataType: "json"
        }).then(function(ddd) {
            responseData.append('document_id', document_id.toString());
            var encryptedKey = stringToArrayBuffer(window.atob(ddd['key']));
            decryptAESKey(sessionStorage.getItem("certificate"), sessionStorage.getItem("privateKey"), encryptedKey)
                .then(function(decryptedKey) {
                    importAESKey(decryptedKey).then(function(AESKey) {
                        encryptAES(event.target.result, AESKey).then(function(resultData) {
                            responseData.append('data', window.btoa(arrayBufferToString(resultData['data'])));
                            responseData.append('binary', window.btoa(resultData['binary']));
                            responseData.append('size', $("#id_filefield")[0].files[0].size)
                            responseData.append('iv', window.btoa(uint8ArrayToString(resultData['iv'])));
                            $.ajax({
                                url: "/resources/document/version/",
                                method: "POST",
                                data: responseData,
                                processData: false,
                                contentType: false,
                                dataType: "json",
                            }).done(function(response) {
                                updateDocumentInTable(document_id, response['data']);
                                $("#file_upload_alert").css("display", "none");
                                $("#newfilebackgrounddiv").css("display", "none");
                            }).fail(function(err) {
                                console.error('Error while posting data to server.' + err)
                            });
                            // now we can send encrypted document, iv and keys to server
                        }).catch(function(err) {
                            console.error('Error while Encrypting document: ' + err);
                        });
                    }).catch(function(err) {
                        console.error('Error while importing AES key' + err);
                    });
                }).catch(function(err) {
                    console.error('Error while decrypting key: ' + err);
                });
        });
    };
    if ($("#id_filefield")[0].files[0] === undefined) {
        $("#file_upload_alert").html("Please select a file to upload.");
        $("#file_upload_alert").css("display", "block");
    } else if ($("#id_filefield")[0].files[0].size > 10485760) {
        $("#file_upload_alert").html("File too large! Must be < 10MB");
        $("#file_upload_alert").css("display", "block");
    } else {
        fileReader.readAsArrayBuffer($("#id_filefield")[0].files[0]);
    }
}

var newDocumentUpload = function newDocumentUpload() {
    /*
     * First get public keys of collaborators on new file
     * for simplicity we will assume all users of our organization
     * will have access to the file.
     */
    var responseData = new FormData();
    var fileReader = new FileReader();
    fileReader.onerror = function(err) {
        console.error('Could not load file: ' + err)
    }
    fileReader.onload = function(event) {
        var requestData = {
            organization: $("#id_organizations").val()
        }
        $.ajax({
            url: "/resources/organization/certificates/",
            method: "GET",
            data: requestData,
            dataType: "json"
        }).done(function(response) {
            var certificates = response['data']['certificates']
            if (certificates.length === 0) {
                $("#file_upload_alert").html("No collaborators were specified.");
                $("#file_upload_alert").css("display", "block");
                return;
            }
            responseData.append('organization', $("#id_organizations").val());
            generateAESKey().then(function(initialAESKey) {
                encryptAES(event.target.result, initialAESKey).then(function(resultData) {
                    // responseData.append('data', new Blob([resultData['data']]), $("#id_filefield")[0].files[0].name);
                    responseData.append('data', window.btoa(arrayBufferToString(resultData['data'])));
                    responseData.append('binary', window.btoa(resultData['binary']));
                    responseData.append('name', $("#id_filefield")[0].files[0].name)
                    responseData.append('size', $("#id_filefield")[0].files[0].size)
                    responseData.append('iv', window.btoa(uint8ArrayToString(resultData['iv'])));
                    var signators = [];
                    $("tr.signator").each(function(){
                        var $this = $(this);
                        if ($this.find("input:checkbox").is(":checked")) {
                            signators.push($this.find("td.id").html());
                        }
                    })
                    responseData.append('signators', JSON.stringify(signators));
                    exportAESKey(initialAESKey).then(function(exportedAESKey) {
                        var promises = [];
                        var userKeys = {};
                        for (var userId in certificates) {
                            promises.push(encryptAESKey(certificates[userId], userId, exportedAESKey).then(
                                function(result) {
                                    // responseData.append('user_'+result.userId.toString(), window.btoa(arrayBufferToString(result.encryptedKey)));
                                    userKeys[result.userId.toString()] = window.btoa(arrayBufferToString(result.encryptedKey));
                                }
                            ));
                        }
                        Promise.all(promises).then(function() {
                            responseData.append('keys', JSON.stringify(userKeys))
                            $.ajax({
                                url: "/resources/document/",
                                method: "POST",
                                data: responseData,
                                processData: false,
                                contentType: false,
                                dataType: "json",
                            }).done(function(response) {
                                appendDocumentToTable(response['data']);
                                $("#file_upload_alert").css("display", "none");
                                $("#newfilebackgrounddiv").css("display", "none");
                            }).fail(function(err) {
                                console.error('Error while posting data to server.' + err)
                            });
                            // now we can send encrypted document, iv and keys to server
                        }).catch(function(err) {
                            console.error('Error while encrypting user keys.' + err);
                        });
                    }).catch(function(err) {
                        console.error('Error while exporting AES key.' + err);
                    });
                }).catch(function(err) {
                    console.error('Error while encrypting data.' + err);
                });
            }).catch(function(err) {
                console.error('Error while generating AES key: ', err);
            });
        }).fail(function(err) {
            console.error('Certificates could not be loaded: ' + err);
        });
    };
    if ($("#id_filefield")[0].files[0] === undefined) {
        $("#file_upload_alert").html("Please select a file to upload.");
        $("#file_upload_alert").css("display", "block");
    } else if ($("#id_filefield")[0].files[0].size > 10485760) {
        $("#file_upload_alert").html("File too large! Must be < 10MB");
        $("#file_upload_alert").css("display", "block");
    } else {
        fileReader.readAsArrayBuffer($("#id_filefield")[0].files[0]);
    }
}

// helper function to get encrypted document from server
var getEncryptedDocument = function getEncryptedDocument(document_id, version) {
    var requestData = {
        document_id: document_id,
        version: version
    };
    return $.ajax({
        url: "/resources/document/version/",
        method: "GET",
        data: requestData,
        dataType: "json"
    });
}

// get document decryption data from the server
var getDDD = function getDDD(document_id, version) {
    var requestData = {
        document_id: document_id,
        version: version
    };
    return $.ajax({
        url: "/resources/get/ddd/",
        method: "GET",
        data: requestData,
        dataType: "json"
    });
}

var getDocumentDetails = function getDocumentDetails(document_id) {
    /*
     * fetch details about document from server
     */
    var requestData = {
        document_id: document_id
    };
    return $.ajax({
        url: "/resources/document/details/",
        method: "GET",
        data: requestData,
    });

}

var getDocumentVersionDetails = function getDocumentVersionDetails(document_id, version) {
    /*
     * fetch details about specific document version from server
     */
    var requestData = {
        document_id: document_id,
        version: version
    };
    return $.ajax({
        url: "/resources/documentversion/details/",
        method: "GET",
        data: requestData,
    });
}

var getDocumentSignatures = function getDocumentSignatures(document_id) {
    /*
     * Returns all signatures for given document id
     */
    var requestData = {
        document_id: document_id,
    };
    return $.ajax({
        url: "/resources/document/signaturesbatch/",
        method: "GET",
        data: requestData,
        dataType: "json"
    });
}


var getDocumentVersionSignatures = function getDocumentVersionSignatures(document_id, version) {
    /*
     * Returns all signatures for given document id
     */
    var requestData = {
        document_id: document_id,
        version: version
    };
    return $.ajax({
        url: "/resources/documentversion/signaturesbatch/",
        method: "GET",
        data: requestData,
        dataType: "json"
    });
}

var getCertificateByEmail = function getCertificateByEmail(email) {
    /*
     * Request certificate of user specified by email
     */
    var requestData = {};
    if (email != null)
        requestData.email = email;
    return $.ajax({
        url: "/resources/get/certificate/",
        method: "GET",
        data: requestData,
        dataType: "json"
    });
}

var getCertificateByID = function getCertificateByID(user_id) {
    /*
     * Request certificate of user specified by user id
     */
    var requestData = {};
    if (user_id != null)
        requestData.user_id = user_id;
    return $.ajax({
        url: "/resources/get/certificate/",
        method: "GET",
        data: requestData,
        dataType: "json"
    });
}

var deleteDocument = function deleteDocument(document_id) {
    /*
     * Delete document from server. This is irreversible operation.
     */
    var requestData = {'document_id': document_id}
    return $.ajax({
        url: "/resources/document/",
        method: "POST",
        data: requestData,
        dataType: "json",
        headers: { 'X-METHODOVERRIDE': 'DELETE' }
    });
}

var lockDocument = function lockDocument(document_id) {
    /*
     * Lock document for updates if possible and returns timerange
     */
    var requestData = {'document_id': document_id}
    return $.ajax({
        url: "/resources/lock/",
        method: "POST",
        data: requestData,
        dataType: "json"
    });
}

var getOrganizationSignators = function getOrganizationSignators(organization_id) {
    /*
     * Request users who has permission to sign documents in organization
     */
    var requestData = {};
    if (organization_id != null)
        requestData.organization_id = organization_id;
    return $.ajax({
        url: "/resources/organization/signators/",
        method: "GET",
        data: requestData,
        dataType: "json"
    });
}

var getCollaborationHistory = function getCollaborationHistory(document_id) {
    /*
     * Return collaboration history formatted as a table
     */
    var requestData = {};
    if (document_id != null)
        requestData.document_id = document_id;
    return $.ajax({
        url: "/resources/document/history/",
        method: "GET",
        data: requestData
    });
}

var setOrganizationSignators = function getSetOrganizationSignators(signators) {
    $("#newfile_signators_table").html('');
    $("#newfile_signators_table").html('<caption>Select mandatory signators</caption>');
    for (var id in signators) {
        var row = `<tr class="signator">
                        <td class="id">${id}</td>
                        <td>${signators[id]}</td>
                        <td><input class="checkbox" type="checkbox"/>
                    </tr>`;
        $("#newfile_signators_table").append(row);
    }
}



var documentDiff = function documentDiff(doc1, doc2, v1, v2) {
    // get the baseText and newText values from the two textboxes, and split them into lines
    var base = difflib.stringAsLines(doc1);
    var newtxt = difflib.stringAsLines(doc2);

    // create a SequenceMatcher instance that diffs the two sets of lines
    var sm = new difflib.SequenceMatcher(base, newtxt);

    // get the opcodes from the SequenceMatcher instance
    // opcodes is a list of 3-tuples describing what changes should be made to the base text
    // in order to yield the new text
    var opcodes = sm.get_opcodes();
    // var diffoutputdiv = $("diffoutput");
    // while (diffoutputdiv.firstChild) diffoutputdiv.removeChild(diffoutputdiv.firstChild);
    //var contextSize = $("contextSize").value;

    var contextSize = contextSize ? contextSize : null;

    // build the diff view and add it to the current DOM
    return diffview.buildView({
        baseTextLines: base,
        newTextLines: newtxt,
        opcodes: opcodes,
        // set the display titles for each resource
        baseTextName: `Version ${v1}`,
        newTextName: `Version ${v2}`,
        contextSize: contextSize,
        viewType: $("inline").checked ? 1 : 0
    });
}

var deleteDocumentDialog = function deleteDocumentDialog(document_id, tablerow) {
    /*
     * Show dialog for deleteing document from server
     * TODO: show dialog window :)
     */
    deleteDocument(document_id).then(
        function(result) {
            if (result['status'] != 'OK') {
                console.error('Could not delete document: ', result);
                return;
            }
            $("#doctable tr.selected").remove();
        }
    ).fail(function(error){
        console.error('Could not delete document: ', error);
    })
}


/*
 * Returns requested document version, if ver==0, latest version of document
 * is returned.
 */
var getDecryptedDocument = function getDecryptedDocument(document_id, version) {
    var encryptedDocument;
    var iv;
    var sequence = Promise.resolve()
    return $.when(
        getEncryptedDocument(document_id, version),
        getDDD(document_id, version)
    ).then(function(encDoc, ddd) {
        encryptedDocument = stringToArrayBuffer(window.atob(encDoc[0]['data']['document']));
        iv = stringToUint8Array(window.atob(ddd[0]['iv']));
        var encryptedKey = stringToArrayBuffer(window.atob(ddd[0]['key']));
        return decryptAESKey(sessionStorage.getItem("certificate"), sessionStorage.getItem("privateKey"), encryptedKey)
            .then(function(decryptedKey) {
                return importAESKey(decryptedKey).then(function(AESKey) {
                    return decryptAES(encryptedDocument, iv, AESKey).then(function(decryptedDocument) {
                        return {'data': decryptedDocument, 'binary': encDoc[0]['data']['binary']};
                    }).catch(function(err){
                        console.error('Error while decrypting document: ', err);
                    });
                }).catch(function(err){
                    console.error('Error while importing AESKey');
                });
            }).catch(function(err){
                console.error('Error while decrypting AES Key: ', err);
            });
    }).fail(function(err) {
        console.error('Error while downloading document from server: ', err);
    });
}

var createSignature = function createSignature(document_id, version) {
    /*
     * Sign latest version of requested document
     */
    var postData = new FormData();
    getDecryptedDocument(document_id, version).then(function(result) {
        result.then(function(doc) {
            signDocument(
                doc['data'],
                sessionStorage.getItem("certificate"),
                sessionStorage.getItem("privateKey")).then(function(signature) {
                postData.append('signature', signature);
                postData.append('document_id', document_id);
                postData.append('version', version);
                // TODO: posting for latest version, which can change!
                $.ajax({
                    url: "/resources/document/signature/",
                    method: "POST",
                    data: postData,
                    processData: false,
                    contentType: false,
                    dataType: "json",
                }).done(function(response) {
                    console.log(response);
                }).fail(function(error) {
                    console.error('Failed to post signature: ', error);
                })
            })
        }).catch(function(err) {
            console.log('Failure: ', err);
        })
    });
}

var verifySignatures = function verifySignatures(document_id, version, signatures){
    /*
     * Downloads document and verify signatures given in structure.
     * Little cumbersome, since structure is of non-standard type,
     * i.e. email: [username, signature]
     * TODO: fix this
     */
    getDecryptedDocument(document_id, version).then(
        function(result){
            result.then(function(doc) {
                var promises = [];
                for (var email in signatures) {
                    promises.push(Promise.resolve(
                        getCertificateByEmail(email).then(
                            function(certResponse){
                                if (certResponse.status != 'OK') {
                                    console.error('Error while downloading certificate: ', cert.response)
                                    return;
                                }
                                return verifyCMSSignature(signatures[email][1], certResponse['certificate'], doc['data']).then(
                                    function(result) {
                                        return result;
                                    }
                                )
                            }
                        ))
                    )
                }
                Promise.all(promises).then(
                    function(results) {
                        for (var r in results) {
                            if (!r) {
                                $("#sdetailsalert").html('Invalid signatures!')
                                $("#sdetailsalert").css("display", "block");
                                return;
                            }
                        }
                        $("#sdetailsalert").html('Signatures OK!');
                        $("#sdetailsalert").css("color", "green");
                        $("#sdetailsalert").css("display", "block");
                    }
                )
            })
        }
    )
}

var showDocumentVersionSignatures = function showDocumentVersionSignatures(document_id, version) {
    /*
     * Show signatures of particular version of document
     */
    $.when(getDocumentVersionSignatures(document_id, version).then(
        function(result) {
            if (result['status'] != 'OK') {
                console.error(result);
                return;
            }
            var table = ''
            for (var email in result['data']['signatures']) {
                var username = result['data']['signatures'][email][0]
                var parsed = parseCMSSignature(result['data']['signatures'][email][1]);
                var date = new Date(parsed['utctime']);
                table = table + `<tr>
                                    <td>${username}</td>
                                    <td>${email}</td>
                                    <td>${date.toUTCString()}</td>
                                </tr>`;
            }
            var title = `Version ${result['data']['version']} signatures`;
            $("#sdetailsh3").html(title);
            $("#sdetailstable").html(table);
            $("#sdetailsverifybtn").click(
                function(){
                    requestedCredentials(verifySignatures, document_id, version, result['data']['signatures']);
                }
            );
            $("#sdetailsbackgrounddiv").css('display', 'block');
        }
    ))
}

var showDocumentSignatures = function showDocumentSignatures(document_id) {
    /*
     * show details of signatures for any document version
     */
    $.when(getDocumentSignatures(document_id)).then(
        function(result){
            if (result['status'] != 'OK') {
                console.error(result);
                return;
            }
            for (var version in result['data']) {
                var div = `<div class="signaturediv" id="signaturediv_${version}">Version ${version}
                                <div class="signaturetablediv" id="signaturetablediv_${version}">
                                </div>
                            </div>`
                $("#sdetailsdiv").append(div);
                $("#signaturediv_" + version).click(
                    function(){
                        var table = '<table>'
                        for (var userID in result['data'][version]) {
                            table = table + `<tr><td>${userID}</td></tr>`;
                        }
                        table = table + `</table>`
                        $("#signaturetablediv_" + version).val(table);
                        $("#signaturediv_" + version).toggle();
                    }
                )
            }
            var button = '<p class="pbtn" id="sdismissbtn">OK</p>';
            $("#sdetailsdiv").append(button);
            $("#sdismissbtn").click(
                function(){
                    $("#sdetailsbackgrounddiv").css('display', 'none');
                }
            )
            $("#sdetailsbackgrounddiv").css('display', 'block');
    }).fail(function(err){
        console.error('Error while downloading signatures from server', err);
    })
}

var compareDocuments = function compareDocuments(document_id, version1, version2) {
    /*
     * compares two versions of same document
     */
    var promises = [];
    promises.push(getDecryptedDocument(document_id, version1));
    promises.push(getDecryptedDocument(document_id, version2));
    Promise.all(promises).then(
        function(result) {
            var doc1 = arrayBufferToString(result[0]['data']);
            var doc2 = arrayBufferToString(result[1]['data']);
            var doc1binary = result[0]['binary'];
            var doc2binary = result[1]['binary'];
            var diff = documentDiff(doc1, doc2, version1, version2);
            $("#ddiffviewdiv").html(diff);
            $("#ddiffbackgrounddiv").css("display", "block");
        }
    ).catch(
        function(err) {
            console.error('Failed while downloading documents');
        }
    )
}

var documentDetailsDialog = function documentDetailsDialog(document_id, version, document_name) {
    /*
     * Show details of requsted document
     */
    $.when(
        getDocumentDetails(document_id),
        getDocumentVersionDetails(document_id, version)
    ).done(function(documentDetails, versionDetails) {
        $("#ddetailsspan").html(documentDetails[0]);
        $("#dversiondetailsspan").html(versionDetails[0]);
        $("#dversionselect").val(version);
        $("#ddetailsbackgrounddiv").css("display", "block");
        $("#ddownloadbtn").click(function() {
            requestedCredentials(downloadDocument, document_id, $("#dversionselect").val(), document_name);
        });
        $('#dversionselect').change(function() {
            getDocumentVersionDetails(document_id, $(this).find('option:selected').val()).then(
                function(versionDetails) {
                    $("#dversiondetailsspan").html(versionDetails);
                }
            ).fail(function(err) {
                console.error('Error while getting document version details.', err);
            });
        });
        $("#dverifysignaturesbtn").click(function() {
            showDocumentVersionSignatures(document_id, $('#dversionselect').val());
        });
    }).fail(function(err) {
        console.error('Error while getting document details. ', err);
    });
}

var downloadDocument = function downloadDocument(document_id, version, name) {
    getDecryptedDocument(document_id, 0).then(function(value) {
        value.then(function(result) {
            var a = document.createElement("a");
            a.style = "display: none";
            var blob = new Blob([result['data']], {type: 'application/octet-binary'});
            var url = URL.createObjectURL(blob);
            a.href = url;
            a.download = name;
            a.click();
            window.URL.revokeObjectURL(url);
        }).catch(function(err){
            console.error('Couldnt download document: ', err);
        })
    }).fail(function(err) {
        console.error('Error while fetching document from server: ' + err);
    });
}

var lockDocumentDialog = function lockDocumentDialog(document_id) {
    /*
     * Lock document for updates or notifies user if document already locked
     */
    // show some dialog and on click ....
    var duration = 120;
    $.when(lockDocument(document_id, duration)).then(
        function(result) {
            console.log(result);
        }
    )
}

var getNewVersionUploadForm = function getNewVersionUploadForm(document_id) {
    var requestData = {
        document_id: document_id
    };
    return $.ajax({
        url: "/resources/get/newversionuploadform/",
        method: "GET",
        data: requestData
    });
}

var uploadNewVersionDialog = function uploadNewVersionDialog(document_id) {
    $.when(getNewVersionUploadForm(document_id)).done(
        function(result) {
            $("#newfilebackgrounddiv").html(result);
            $("#newfilebackgrounddiv").css("display", "block");
            $("#newversionform #newversion_confirm").click(function() {
                requestedCredentials(newVersionUpload, document_id);
            });
            $("#newversionform #newversion_cancel").click(function() {
                $("#file_upload_alert").css("display", "none");
                $("#newfilebackgrounddiv").css("display", "none");
            });
    }).fail(function() {
        alert('Error occured while accesing server!');
    });
}

var compareDocumentsDialog = function compareDocumentsDialog(document_id, last_version) {
    /*
     * Simple document comparison for text files
     */
    var table = '<table>';
    for (var v = 1; v <= last_version; v++) {
        var row = `<tr>
                    <td>Version ${v}</td>
                    <td><input class="verticalbuttons" type="radio" name="d1buttons" value="${v}"></td>
                    <td><input class="verticalbuttons" type="radio" name="d2buttons" value="${v}"></td>
                </tr>`
        table = table + row;
    }
    table = table + `</table>`;
    $("#dcomparetable").html(table);
    $("#dcomparecomparebtn").click(
        function() {
            var val1 = $("input[name=d1buttons]:checked").val();
            var val2 = $("input[name=d2buttons]:checked").val();
            if ( val1 === val2 && val1 != null) {
                $("#dcomparealert").text("You selected same versions.");
                $("#dcomparealert").css("display", "block");
            } else if (val1 === undefined || val2 === undefined) {
                $("#dcomparealert").text("Please select versions you want to compare.");
                $("#dcomparealert").css("display", "block");
            }
            else {
                requestedCredentials(compareDocuments, document_id, val1, val2);
                $("#dcomparealert").css("display", "none");
            }
        }
    )
    $("#dcomparebackgrounddiv").css("display", "block");
}

var archiveDocumentDialog = function archiveDocumentDialog(document_id) {
    /*
     * Functionality to archive document to not 'hamper' in current view
     */
}

var uploadNewFileDialog = function uploadNewFileDialog() {
    /*
     * Show dialog for new file upload
     */
    $.ajax({
        url: "/resources/newdocumentuploadform/",
        method: "GET"
    }).done(function(data) {
        $("#newfilebackgrounddiv").html(data);
        $("#id_organizations").change(function(){
            getOrganizationSignators($(this).find('option:selected').val()).then(
                function(result) {
                    if (result.status != 'OK') {
                        console.error('Error occured: ', result.message)
                    } else
                        setOrganizationSignators(result.data.signators);
                }
            ).fail(function(err){
                console.error('Couldnt get signators: ', err);
            })
        });
        $("#id_organizations").change();
        $("#newfilebackgrounddiv").css("display", "block");
        $("#newfileform #newfile_confirm").click(newDocumentUpload);
        $("#newfileform #newfile_cancel").click(function() {
            $("#file_upload_alert").css("display", "none");
            $("#newfilebackgrounddiv").css("display", "none");
        });
    }).fail(function() {
        alert('Error occured while accesing server!');
    });
}

var documentHistoryDialog = function documentHistoryDialog(document_id) {
    /*
     * Show collaboration hisotory for given document.
     */
    getCollaborationHistory(document_id).then(
        function(result) {
            $("#dhistorytablediv").html(result);
            $("#dhistorybackgrounddiv").css("display", "block");
        }
    ).fail(function(err){
        console.error("Couldn't fetch document history: ", err);
    })
}

/*
 * Show menu after performing click on the document
 */
var showDocumentMenu = function showDocumentMenu(global_event) {
    var document_id = $(global_event.target).closest("tr").find(".id").text();
    var document_version = $(global_event.target).closest("tr").find(".version").text();
    var document_name = $(global_event.target).closest("tr").find(".name").text();
    $(event.target).closest("tr").addClass('selected').siblings().removeClass("selected");
    $("#menu_get_latest").click(
        function(event) {
            requestedCredentials(downloadDocument, document_id, 0, document_name);
            unbindMenuItems();
            $("#filemenudiv").css("display", "none");
        }
    );
    $("#menu_upload_new_version").click(
        function() {
            uploadNewVersionDialog(document_id);
            unbindMenuItems();
            $("#filemenudiv").css("display", "none");
        }
    );
    $("#menu_sign_latest").click(
        function(event) {
            requestedCredentials(createSignature, document_id, document_version);
            unbindMenuItems();
            $("#filemenudiv").css("display", "none");
        }
    );
    $("#menu_delete").click(
        function(event) {
            deleteDocumentDialog(document_id, global_event);
            unbindMenuItems();
            $("#filemenudiv").css("display", "none");
        }
    );
    $("#menu_compare").click(
        function(event) {
            compareDocumentsDialog(document_id, document_version);
            unbindMenuItems();
            $("#filemenudiv").css("display", "none");
        }
    );
    /* // also disabled
    $("#menu_archive").click(
        function(event) {
            archiveDocumentDialog(document_id);
            $("#filemenudiv").css("display", "none");
        }
    );
    $("#menu_lock").click(function(event) {
        lockDocumentDialog(document_id);
        $("#filemenudiv").css("display", "none");
    })
    */
    $("#menu_more").click(
        function(event) {
            documentDetailsDialog(document_id, document_version, document_name);
            unbindMenuItems();
            $("#filemenudiv").css("display", "none");
        }
    );
    $("#menu_history").click(
        function(event) {
            documentHistoryDialog(document_id, document_version);
            unbindMenuItems();
            $("#filemenudiv").css("display", "none");
        }
    );
    $("#ddiffdismissbtn").click(
        function() {
            $("#ddiffviewdiv").empty();
            $("#ddiffbackgrounddiv").css("display", "none");
        }
    );

    /* // disable this for now and ever
    $("#menu_signatures").click(function(event) {
        $("#filemenudiv").css("display", "none");
        showDocumentSignatures(document_id);
    });
    */
    $("#filemenudiv").css({
        'top': mouseY,
        'left': mouseX,
        'display': "block",
    });
}

var mouseX;
var mouseY;
$(document).mousemove(function(e) {
    mouseX = e.pageX;
    mouseY = e.pageY;
});

var unbindMenuItems = function unbindMenuItems() {
    $("#menu_get_latest").off('click');
    $("#menu_upload_new_version").off('click');
    $("#menu_sign_latest").off('click');
    $("#menu_delete").off('click');
    $("#menu_compare").off('click');
    $("#menu_more").off('click');
    $("#menu_history").off('click');
}

$(document).ready(function() {
    // load common functionality
    baseScript();
    $("#newfilebtn").click(function() {
        uploadNewFileDialog();
    });
    $("#doctable").click(
        function(event) {
            showDocumentMenu(event);
        }
    );
    // some cancel buttons
    $("#sdetailsdismissbtn").click(
        function(){
            $("#sdetailsbackgrounddiv").css('display', 'none');
        }
    );
    $("#ddetailsdismissbtn").click(
        function() {
            $("#ddetailsbackgrounddiv").css("display", "none");
        }
    );
    $("#dcomparedismissbtn").click(
        function(){
            $("#dcomparebackgrounddiv").css("display", "none");
        }
    );
    $("#ddiffdismissbtn").click(
        function(){
            $("#ddiffbackgrounddiv").css("display", "none");
        }
    );
    $("#dhistorydismissbtn").click(
        function(){
            $("#dhistorybackgrounddiv").css("display", "none");
        }
    );
    // Hide the menu menu after clicking outside of menu or table
    $(document).click(
        function(event) {
            if (!$(event.target).closest('#filemenudiv').length && !$(event.target).closest('#doctable').length) {
                unbindMenuItems();
                $("#filemenudiv").css("display", "none");
            }
        }
    );
    $("#doctable").tablesorter();
});
