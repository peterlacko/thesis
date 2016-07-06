/*
 * Author: Peter Lacko
 * Year: 2016
 */

/*
 * Ensure that csrf token is sent with every request
 */
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});



var baseScript = function baseScript() {
    $("#keypassbtn").click(function() {
        $("#keypassinput").val('');
        $.when(requestPrivateKey()).then(
            function(privateKey) {
                if (privateKey != null) {
                    setPrivateKey(privateKey)
                } else {
                    alert('Key already decrypted!');
                }
            }
        )
    });
}

var setPrivateKey = function setPrivateKey(privateKey, args) {
    $("#keypassbackgrounddiv").css("display", "block");
    $("#keypassform #keypass_confirm").click(function(){
        var sequence = parse_PKCS12(privateKey, $("#keypassinput").val());
        sequence.then(
            function(pkcs8){
                sessionStorage.setItem("privateKey", pkcs8);
                $("#keypassbackgrounddiv").css("display", "none");
                if (args != null) {
                    args[0].apply(this, Array.prototype.slice.call(args, 1));
                }
            }
        ).catch(function(){
            $("#keypass_request_alert").html("Incorrect Password!.");
            $("#keypass_request_alert").css("display", "block");
            return false;
        });
        return false;
    });
    $("#keypassform #keypass_cancel").click(function(){
        $("#keypassform #keypass_confirm").off("click");
        $("#keypassbackgrounddiv").css("display", "none");
    });
}

var requestPrivateKey = function requestPrivateKey() {
    if (sessionStorage.getItem("privateKey") == null) {
        return $.ajax({
            url: "/resources/get/privkey/",
            method: "GET",
            dataType: "json"
        }).then(function(response) {
            if (response['status'] != 'OK')
                console.error('Error. Server response: ', response);
            else
                return response['data']['pkcs12key'];
        }).fail(function() {
            alert('Error while loading key from server!');
        });
    }
};

var requestCertificate = function requestCertificate() {
    if (sessionStorage.getItem("certificate") == null){
        return $.ajax({
            url: "/resources/get/certificate/",
            method: "GET",
            dataType: "json"
        }).then(function(response){
            if (response['certificate'] != undefined)
                return response['certificate'];
            else
                console.error('Error. Server response: ', response);
        }).fail(function(err){
            alert("Certificate could not be loaded from the server!");
        });
    }
}

var requestedCredentials = function requestCredentials() {
    /*
     * This function behaves as a decorator and MUST be used as a callback
     * handler. It passes callback further if credentials are not available in sessionStorage
     * or executes immediately if they are present.
     */
    var args = arguments;
    $.when(requestCertificate(), requestPrivateKey()).then(
        function(certificate, privateKey){
            if (certificate != null)
                sessionStorage.setItem("certificate", certificate);
            if (privateKey != null)
                setPrivateKey(privateKey, args);
            else {
                args[0].apply(this, Array.prototype.slice.call(args, 1));
            }
    }).fail(
        function(err) {
            console.error('Could not download credentials: ', err);
        }
    )
}

// neccessary for protecting against csfr attack
// TODO: could be manually loaded only for certain files
var getCookie = function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

var csrftoken = getCookie('csrftoken');

var csrfSafeMethod = function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
