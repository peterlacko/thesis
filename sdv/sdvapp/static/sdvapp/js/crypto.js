/*
 * Author: Peter Lacko
 * Year: 2016
 */

'use strict';

function formatPEM(pem_string, label) {
    /// <summary>Format string in order to have each line with length equal to 63</summary>
    /// <param name="pem_string" type="String">String to format</param>

    var string_length = pem_string.length;
    var result_string = "-----BEGIN " + label + '-----\r\n';

    for (var i = 0, count = 0; i < string_length; i++, count++) {
        if (count > 63) {
            result_string = result_string + "\r\n";
            count = 0;
        }
        result_string = result_string + pem_string[i];
    }
    return result_string + '\r\n-----END ' + label + '-----\r\n';
}
//*********************************************************************************
function arrayBufferToString(buffer) {
    /// <summary>Create a string from ArrayBuffer</summary>
    /// <param name="buffer" type="ArrayBuffer">ArrayBuffer to create a string from</param>

    var result_string = "";
    var view = new Uint8Array(buffer);
    for (var i = 0; i < view.length; i++) {
        result_string = result_string + String.fromCharCode(view[i]);
    }
    return result_string;
}
//*********************************************************************************
function stringToArrayBuffer(str) {
    /// <summary>Create an ArrayBuffer from string</summary>
    /// <param name="str" type="String">String to create ArrayBuffer from</param>

    var stringLength = str.length;
    var resultBuffer = new ArrayBuffer(stringLength);
    var resultView = new Uint8Array(resultBuffer);
    for (var i = 0; i < stringLength; i++)
        resultView[i] = str.charCodeAt(i);
    return resultBuffer;
}
//*********************************************************************************
function uint8ArrayToString(arr) {
    /// Create an Uint8Array from given string
    var resultString = "";
    var arrLength = arr.length;
    for (var i = 0; i < arrLength; i++)
        resultString = resultString + String.fromCharCode(arr[i]);
    return resultString;
}
//*********************************************************************************
function stringToUint8Array(str) {
    /// create a string from given Uint8Array
    var strLength = str.length
    var resultArray = new Uint8Array(strLength);
    for (var i = 0; i < strLength; i++)
        resultArray[i] = str.charCodeAt(i);
    return resultArray;
}

// Create PKCS#10
//*********************************************************************************
function create_PKCS10(username, email, organization) {
    /// create Certificate Request from given information
    // Initial variables
    var sequence = Promise.resolve();

    var pkcs10_simpl = new org.pkijs.simpl.PKCS10();

    var publicKey;
    var privateKey;
    var finalCSR;

    // always use sha-256
    var hash_algorithm = "sha-256";

    var signature_algorithm_name = "RSASSA-PKCS1-V1_5";

    // Get a "crypto" extension
    var crypto = org.pkijs.getCrypto();
    if (typeof crypto == "undefined") {
        alert("No WebCrypto extension found");
        return;
    }

    // Put a static values
    pkcs10_simpl.version = 0;

    pkcs10_simpl.subject.types_and_values.push(
        new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.3", // CN
            value: new org.pkijs.asn1.UTF8STRING({
                value: username
            })
        }));
    pkcs10_simpl.subject.types_and_values.push(
        new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "1.2.840.113549.1.9.1", // emailAddress
            value: new org.pkijs.asn1.UTF8STRING({
                value: email
            })
        }));
    pkcs10_simpl.subject.types_and_values.push(
        new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.6", // C
            value: new org.pkijs.asn1.UTF8STRING({
                value: "CZ"
            })
        }));
    pkcs10_simpl.subject.types_and_values.push(
        new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.7", // L
            value: new org.pkijs.asn1.UTF8STRING({
                value: "Brno"
            })
        }));
    pkcs10_simpl.subject.types_and_values.push(
        new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.10", // O
            value: new org.pkijs.asn1.UTF8STRING({
                value: organization
            })
        }));
    pkcs10_simpl.attributes = new Array();

    // Create a new key pair
    sequence = sequence.then(
        function() {
            // Get default algorithm parameters for key generation
            var algorithm = org.pkijs.getAlgorithmParameters(signature_algorithm_name, "generatekey");
            if ("hash" in algorithm.algorithm)
                algorithm.algorithm.hash.name = hash_algorithm;

            return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
        }
    );

    // Store new key in an interim variables
    sequence = sequence.then(
        function(keyPair) {
            publicKey = keyPair.publicKey;
            privateKey = keyPair.privateKey;
        },
        function(error) {
            alert("Error during key generation: " + error);
        }
    );

    // Exporting public key into "subjectPublicKeyInfo" value of PKCS#10
    sequence = sequence.then(
        function() {
            return pkcs10_simpl.subjectPublicKeyInfo.importKey(publicKey);
        }
    );

    // SubjectAltName
    sequence = sequence.then(
        function(result) {
            return crypto.digest({
                name: "SHA-1"
            }, pkcs10_simpl.subjectPublicKeyInfo.subjectPublicKey.value_block.value_hex);
        }
    ).then(
        function(result) {
            pkcs10_simpl.attributes.push(new org.pkijs.simpl.ATTRIBUTE({
                type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
                values: [(new org.pkijs.simpl.EXTENSIONS({
                    extensions_array: [
                        new org.pkijs.simpl.EXTENSION({
                            extnID: "2.5.29.17",
                            critical: false,
                            extnValue: (new org.pkijs.asn1.UTF8STRING({
                                value: email
                            })).toBER(false)
                        })
                    ]
                })).toSchema()]
            }));
        }
    );

    // Signing final PKCS#10 request
    sequence = sequence.then(
        function() {
            return pkcs10_simpl.sign(privateKey, hash_algorithm);
        },
        function(error) {
            alert("Error during exporting public key: " + error);
        }
    );

    // generate final csr
    sequence = sequence.then(
        function(result) {
            var pkcs10_schema = pkcs10_simpl.toSchema();
            var pkcs10_encoded = pkcs10_schema.toBER(false);

            finalCSR = formatPEM(
                window.btoa(arrayBufferToString(pkcs10_encoded)),
                'CERTIFICATE REQUEST');
        },
        function(error) {
            alert("Error signing PKCS#10: " + error);
        }
    ).then( // set attributes
        function() {
            sequence.keysPromise = Promise.all([
                crypto.exportKey("pkcs8", privateKey),
                crypto.exportKey("spki", publicKey)
            ]).then(function(values) {
                // we don't want private key to be PEM encoded
                // since we are processing it further to create PKCS#12
                sequence.privateKey = window.btoa(
                    arrayBufferToString(values[0]));
                sequence.publicKey = formatPEM(window.btoa(
                        arrayBufferToString(values[1])),
                    'PUBLIC KEY');
                sequence.finalCSR = finalCSR;
                return this;
            })
        });
    return sequence;
}

// ****************************************************************************
function create_PKCS12(pkcs8, password) {
    /// return password protected private key in PKCS#12 format
    var sequence = Promise.resolve();

    var asn1 = org.pkijs.fromBER(stringToArrayBuffer(window.atob(pkcs8)));
    // asn1.verified = true;
    var pkcs8_simpl = new org.pkijs.simpl.PKCS8({
        schema: asn1.result
    });

    // Put initial values for PKCS#12 structures
    var pkcs12 = new org.pkijs.simpl.PFX({
        parsedValue: {
            integrityMode: 0, // Password-Based Integrity Mode
            authenticatedSafe: new org.pkijs.simpl.pkcs12.AuthenticatedSafe({
                parsedValue: {
                    safeContents: [{
                        privacyMode: 1, // Password-Based Privacy Protection Mode
                        value: new org.pkijs.simpl.pkcs12.SafeContents({
                            safeBags: [
                                new org.pkijs.simpl.pkcs12.SafeBag({
                                    bagId: "1.2.840.113549.1.12.10.1.2",
                                    bagValue: new org.pkijs.simpl.pkcs12.PKCS8ShroudedKeyBag({
                                        parsedValue: pkcs8_simpl
                                    })
                                })
                            ]
                        })
                    }]
                }
            })
        }
    });

    sequence = sequence.then(
        function() {
            return pkcs12.parsedValue.authenticatedSafe.parsedValue.safeContents[0].value.safeBags[0].bagValue.makeInternalValues({
                password: stringToArrayBuffer(password),
                contentEncryptionAlgorithm: {
                    name: "AES-CBC", // OpenSSL can handle AES-CBC only
                    length: 128
                },
                hmacHashAlgorithm: "SHA-1", // OpenSSL can handle SHA-1 only
                iterationCount: 100000
            });
        }
    );

    sequence = sequence.then(
        function(result) {
            return pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
                safeContents: [{
                    password: stringToArrayBuffer(password),
                    contentEncryptionAlgorithm: {
                        name: "AES-CBC", // OpenSSL can handle AES-CBC only
                        length: 128
                    },
                    hmacHashAlgorithm: "SHA-1", // OpenSSL can handle SHA-1 only
                    iterationCount: 100000
                }]
            });
        }
    );

    // 'integrity'
    sequence = sequence.then(function() {
        return pkcs12.makeInternalValues({
            password: stringToArrayBuffer(password),
            iterations: 100000,
            pbkdf2HashAlgorithm: "SHA-256", // OpenSSL can not handle usage of PBKDF2, only PBKDF1
            hmacHashAlgorithm: "SHA-256"
        });
    });

    sequence = sequence.then(function() {
        var key = arrayBufferToString(pkcs12.toSchema().toBER(false));
        var pkcs12_key = window.btoa(key);
        return pkcs12_key;
    });
    return sequence
}

function parse_PKCS12(data, password) {
    /// export private key from given payload using provided password
    var sequence = Promise.resolve();
    try {
        var asn1 = org.pkijs.fromBER(
            stringToArrayBuffer(window.atob(data)));
        var pkcs12 = new org.pkijs.simpl.PFX({
            schema: asn1.result
        });
    } catch (err) {
        alert(err);
        return;
    }

    // parse authenticatedSafe
    sequence = sequence.then(function() {
        return pkcs12.parseInternalValues({
            password: stringToArrayBuffer(password),
            checkIntegrity: false // Do not check an integrity since OpenSSL produce HMAC using old PBKDF1 function
        });
    });

    // parse "SafeContents" values
    sequence = sequence.then(function() {
        return pkcs12.parsedValue.authenticatedSafe.parseInternalValues({
            safeContents: [{
                password: stringToArrayBuffer(password)
            }]
        });
    });

    // parse "PKCS8ShroudedKeyBag" value
    sequence = sequence.then(function() {
        return pkcs12.parsedValue.authenticatedSafe.parsedValue.safeContents[0].value.safeBags[0].bagValue.parseInternalValues({
            password: stringToArrayBuffer(password)
        });
    });

    // get pkcs8 private key
    sequence = sequence.then(function() {
        var result = "";
        var pkcs8Buffer = pkcs12.parsedValue.authenticatedSafe.parsedValue.safeContents[0].value.safeBags[0].bagValue.parsedValue.toSchema().toBER(false);
        result += formatPEM(window.btoa(arrayBufferToString(pkcs8Buffer)), 'PRIVATE KEY');
        return result;
    });

    return sequence;
}

/*
 * Set of functions for handling symmetric key cryptography
 */
/*
 * Generate new symmetric key
 */
var generateAESKey = function generateAESKey() {
    return window.crypto.subtle.generateKey({
            name: "AES-GCM",
            length: 128, //can be  128, 192, or 256
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt", "decrypt"]
    ).then(function(key) {
        //returns a key object
        return key;
    }).catch(function(err) {
        console.error(err);
    });
}

/*
 * Export given symmetrickey into it's raw form
 */
var exportAESKey = function exportAESKey(key) {
    return window.crypto.subtle.exportKey(
        "raw", //can be "jwk" or "raw"
        key //extractable must be true
    ).then(function(keydata) {
        //returns the exported key data
        return keydata;
    }).catch(function(err) {
        console.error(err);
    });
}

/*
 * Import symmetric key in raw form
 */
var importAESKey = function importAESKey(key) {
    return window.crypto.subtle.importKey(
            "raw", //can be "jwk" or "raw"
            key, { //this is the algorithm options
                name: "AES-GCM",
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
        )
        .then(function(key) {
            //returns the symmetric key
            return key;
        })
        .catch(function(err) {
            console.error(err);
        });
}

/*
 * Encrypt raw symmetric key with user's public key
 */
var encryptAESKey = function encryptAESKey(certificate, userId, AESKey) {
    var clearCert = certificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, '');
    var certBuffer = stringToArrayBuffer(window.atob(clearCert));
    var asn1 = org.pkijs.fromBER(certBuffer);
    var cert_simpl = new org.pkijs.simpl.CERT({
        schema: asn1.result
    });
    var userData = {
        userId: userId
    };
    // var asn1_publicKey = org.pkijs.fromBER(cert_simpl.subjectPublicKeyInfo.subjectPublicKey.value_block.value_hex);
    // var rsa_publicKey_simple = new org.pkijs.simpl.x509.RSAPublicKey({ schema: asn1_publicKey.result });

    // Initialize encryption parameters
    var oaepHashAlgorithm = "SHA-512";

    // prepare key transport structures
    var oaepOID = org.pkijs.getOIDByAlgorithm({
        name: "RSA-OAEP"
    });
    if (oaepOID === "")
        throw new Error("Can not find OID for OAEP");

    // RSAES-OAEP-params
    var hashOID = org.pkijs.getOIDByAlgorithm({
        name: oaepHashAlgorithm
    });
    if (hashOID === "")
        throw new Error("Unknown OAEP hash algorithm: " + oaepHashAlgorithm);

    var hashAlgorithm = new org.pkijs.simpl.ALGORITHM_IDENTIFIER({
        algorithm_id: hashOID,
        algorithm_params: new org.pkijs.asn1.NULL()
    });

    var rsaOAEPParams = new org.pkijs.simpl.cms.RSAES_OAEP_params({
        hashAlgorithm: hashAlgorithm,
        maskGenAlgorithm: new org.pkijs.simpl.ALGORITHM_IDENTIFIER({
            algorithm_id: "1.2.840.113549.1.1.8", // id-mgf1
            algorithm_params: hashAlgorithm.toSchema()
        })
    });

    // KeyTransRecipientInfo
    var keyInfo = new org.pkijs.simpl.cms.KeyTransRecipientInfo({
        version: 0,
        rid: new org.pkijs.simpl.cms.IssuerAndSerialNumber({
            issuer: cert_simpl.issuer,
            serialNumber: cert_simpl.serialNumber
        }),
        keyEncryptionAlgorithm: new org.pkijs.simpl.ALGORITHM_IDENTIFIER({
            algorithm_id: oaepOID,
            algorithm_params: rsaOAEPParams.toSchema()
        }),
        recipientCertificate: cert_simpl
    });

    // Get recipient's public key
    var currentSequence = Promise.resolve();
    currentSequence = currentSequence.then(function(result) {
        // Get current used SHA algorithm
        var schema = keyInfo.keyEncryptionAlgorithm.algorithm_params;
        var rsaOAEPParams = new org.pkijs.simpl.cms.RSAES_OAEP_params({
            schema: schema
        });

        var hashAlgorithm = org.pkijs.getAlgorithmByOID(rsaOAEPParams.hashAlgorithm.algorithm_id);
        if (("name" in hashAlgorithm) === false)
            return Promise.reject("Incorrect OID for hash algorithm: " + rsaOAEPParams.hashAlgorithm.algorithm_id);

        return keyInfo.recipientCertificate.getPublicKey({
            algorithm: {
                algorithm: {
                    name: "RSA-OAEP",
                    hash: {
                        name: hashAlgorithm.name
                    }
                },
                usages: ["encrypt", "wrapKey"]
            }
        });
    });

    // Encrypt early exported document key on recipient's public key
    currentSequence = currentSequence.then(function(result) {
        return window.crypto.subtle.encrypt({
            name: "RSA-OAEP"
        }, result, AESKey);
    });

    currentSequence = currentSequence.then(function(result) {
        userData['encryptedKey'] = result;
        return userData;
    }).catch(function(error) {
        return Promise.reject(error);
    });
    return currentSequence;
}

/*
 * Decrypt symmetric key into it's raw form using user's private key
 */
var decryptAESKey = function decryptAESKey(certificate, privKey, encryptedAESKey) {
    var clearCert = certificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, '');
    var certBuffer = stringToArrayBuffer(window.atob(clearCert));
    var asn1 = org.pkijs.fromBER(certBuffer);
    var cert_simpl = new org.pkijs.simpl.CERT({
        schema: asn1.result
    });
    var clearPrivkey = privKey.replace(/(-----(BEGIN|END)( NEW)? PRIVATE KEY-----|\n)/g, '');
    var privkeyBuffer = stringToArrayBuffer(window.atob(clearPrivkey));

    // Initialize encryption parameters
    var oaepHashAlgorithm = "SHA-512";

    // prepare key transport structures
    var oaepOID = org.pkijs.getOIDByAlgorithm({
        name: "RSA-OAEP"
    });
    if (oaepOID === "")
        throw new Error("Can not find OID for OAEP");

    // RSAES-OAEP-params
    var hashOID = org.pkijs.getOIDByAlgorithm({
        name: oaepHashAlgorithm
    });
    if (hashOID === "")
        throw new Error("Unknown OAEP hash algorithm: " + oaepHashAlgorithm);

    var hashAlgorithm = new org.pkijs.simpl.ALGORITHM_IDENTIFIER({
        algorithm_id: hashOID,
        algorithm_params: new org.pkijs.asn1.NULL()
    });

    var rsaOAEPParams = new org.pkijs.simpl.cms.RSAES_OAEP_params({
        hashAlgorithm: hashAlgorithm,
        maskGenAlgorithm: new org.pkijs.simpl.ALGORITHM_IDENTIFIER({
            algorithm_id: "1.2.840.113549.1.1.8", // id-mgf1
            algorithm_params: hashAlgorithm.toSchema()
        })
    });

    // KeyTransRecipientInfo
    var keyInfo = new org.pkijs.simpl.cms.KeyTransRecipientInfo({
        version: 0,
        rid: new org.pkijs.simpl.cms.IssuerAndSerialNumber({
            issuer: cert_simpl.issuer,
            serialNumber: cert_simpl.serialNumber
        }),
        keyEncryptionAlgorithm: new org.pkijs.simpl.ALGORITHM_IDENTIFIER({
            algorithm_id: oaepOID,
            algorithm_params: rsaOAEPParams.toSchema()
        }),
        recipientCertificate: cert_simpl
    });

    var currentSequence = Promise.resolve();
    // Import recipient's private key
    currentSequence = currentSequence.then(function(result) {
        // Get current used SHA algorithm
        var schema = keyInfo.keyEncryptionAlgorithm.algorithm_params;
        var rsaOAEPParams = new org.pkijs.simpl.cms.RSAES_OAEP_params({
            schema: schema
        });

        var hashAlgorithm = org.pkijs.getAlgorithmByOID(rsaOAEPParams.hashAlgorithm.algorithm_id);
        if (("name" in hashAlgorithm) === false)
            return Promise.reject("Incorrect OID for hash algorithm: " + rsaOAEPParams.hashAlgorithm.algorithm_id);

        return window.crypto.subtle.importKey("pkcs8",
            privkeyBuffer, {
                name: "RSA-OAEP",
                hash: {
                    name: hashAlgorithm.name
                }
            },
            true, ["decrypt"]);
    });

    // Decrypt encrypted document key
    currentSequence = currentSequence.then(function(result) {
        return window.crypto.subtle.decrypt({
                name: "RSA-OAEP"
            },
            result,
            encryptedAESKey
        )
    });

    return currentSequence;
}

/*
 * Encrypt given data payload with provided key
 */
var encryptAES = function encryptAES(data, key) {
    var result = {
        iv: window.crypto.getRandomValues(new Uint8Array(12))
    };
    return window.crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: result.iv
        },
        key, //from generateKey or importKey above
        data //ArrayBuffer of data you want to encrypt
    ).then(function(encrypted) {
        //returns an ArrayBuffer containing the encrypted data
        result["data"] = encrypted;
        result["binary"] = true;
        return result;
    }).catch(function(err) {
        console.error("Couldn't encrypt data: ", err);
    });
}

/*
 * Decrypt data
 */
var decryptAES = function decryptAES(data, iv, key) {
    return window.crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: iv
        },
        key, //from generateKey or importKey above
        data //ArrayBuffer of the data
    ).then(function(decrypted) {
        //returns an ArrayBuffer containing the decrypted data
        return decrypted;
    }).catch(function(err) {
        console.error("Couldn't decrypt data: ", err);
    });
}

var signDocument = function signDocument(buffer, certificate, privateKey) {
    // #region Initial variables

    var clearCert = certificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, '');
    var certBuffer = stringToArrayBuffer(window.atob(clearCert));
    var asn1 = org.pkijs.fromBER(certBuffer);
    var cert_simpl = new org.pkijs.simpl.CERT({
        schema: asn1.result
    });

    var clearPrivkey = privateKey.replace(/(-----(BEGIN|END)( NEW)? PRIVATE KEY-----|\n)/g, '');
    var privkeyBuffer = stringToArrayBuffer(window.atob(clearPrivkey));
    var importedPrivKey;

    var hash_algorithm = "sha-256";
    var signature_algorithm_name = "RSASSA-PKCS1-V1_5";
    var cms_signed_simpl;

    var sequence = Promise.resolve();
    sequence = sequence.then(function() {
        return window.crypto.subtle.importKey("pkcs8",
            privkeyBuffer, {
                name: "RSASSA-PKCS1-V1_5",
                hash: {
                    name: hash_algorithm
                }
            },
            true, ["sign"]);
    });

    // #region Create a message digest
    sequence = sequence.then(function(result) {
        importedPrivKey = result;
        return window.crypto.subtle.digest({
            name: hash_algorithm
        }, new Uint8Array(buffer));
    }).catch(function(error) {
        console.error('Could not create document hash!: ', error);
    });
    // #endregion

    // #region Combine all signed extensions
    sequence = sequence.then(function(result) {
        var signed_attr = [];

        signed_attr.push(new org.pkijs.simpl.cms.Attribute({
            attrType: "1.2.840.113549.1.9.3",
            attrValues: [
                new org.pkijs.asn1.OID({
                    value: "1.2.840.113549.1.7.1"
                })
            ]
        })); // contentType
        // TODO: get timestamp from server
        signed_attr.push(new org.pkijs.simpl.cms.Attribute({
            attrType: "1.2.840.113549.1.9.5",
            attrValues: [
                new org.pkijs.asn1.UTCTIME({
                    value_date: new Date()
                })
            ]
        })); // signingTime
        signed_attr.push(new org.pkijs.simpl.cms.Attribute({
            attrType: "1.2.840.113549.1.9.4",
            attrValues: [
                new org.pkijs.asn1.OCTETSTRING({
                    value_hex: result
                })
            ]
        })); // messageDigest

        return signed_attr;
    }).catch(function(error) {
        console.error('Failure: ', error);
    });

    // #region Initialize CMS Signed Data structures and sign it
    sequence = sequence.then(function(result) {
        cms_signed_simpl = new org.pkijs.simpl.CMS_SIGNED_DATA({
            version: 1,
            encapContentInfo: new org.pkijs.simpl.cms.EncapsulatedContentInfo({
                eContentType: "1.2.840.113549.1.7.1" // "data" content type
            }),
            signerInfos: [
                new org.pkijs.simpl.CMS_SIGNER_INFO({
                    version: 1,
                    sid: new org.pkijs.simpl.cms.IssuerAndSerialNumber({
                        issuer: cert_simpl.issuer,
                        serialNumber: cert_simpl.serialNumber
                    })
                })
            ],
            certificates: [cert_simpl]
        });

        cms_signed_simpl.signerInfos[0].signedAttrs = new org.pkijs.simpl.cms.SignedUnsignedAttributes({
            type: 0,
            attributes: result
        });

        // We want detached signature
        return cms_signed_simpl.sign(importedPrivKey, 0, hash_algorithm, buffer);
    }).catch(function(error) {
        console.error('Failure: ', error);
    });
    // #endregion

    return sequence.then(function(result) {
        var cms_signed_schema = cms_signed_simpl.toSchema(true);

        var cms_content_simp = new org.pkijs.simpl.CMS_CONTENT_INFO({
            contentType: "1.2.840.113549.1.7.2",
            content: cms_signed_schema
        });

        var cms_signed_schema = cms_content_simp.toSchema(true);
        // #region Make length of some elements in "indefinite form"

        var cmsSignedBuffer = cms_signed_schema.toBER(false);

        // #region Convert ArrayBuffer to String
        var signed_data_string = arrayBufferToString(cmsSignedBuffer);
        // #endregion

        var result_string = formatPEM(window.btoa(signed_data_string), "CMS");
        return result_string;
    }).catch(function(error) {
        console.error("Erorr during signing of CMS Signed Data: " + error);
    });
}

var parseCMSSignature = function parseCMSSignature(CMSData) {
    /*
     * CMSData: base64
     * Returns parsed signature as an objects
     */
    var clearCMSData = CMSData.replace(/(-----(BEGIN|END)( NEW)? CMS-----|\n)/g, '');
    var CMSBuffer = stringToArrayBuffer(window.atob(clearCMSData));
    var asn1 = org.pkijs.fromBER(CMSBuffer);
    var cms_content_simpl = new org.pkijs.simpl.CMS_CONTENT_INFO({ schema: asn1.result });
    var cms_signed_simpl = new org.pkijs.simpl.CMS_SIGNED_DATA({ schema: cms_content_simpl.content });
    var date = cms_signed_simpl.signerInfos[0].signedAttrs.attributes[1].attrValues[0];
    var datetime = `${date.year}-${date.month}-${date.day} ${date.hour}:${date.minute}:${date.second}`;
    var result = {};
    result.utctime = datetime;
    return result;
}

var verifyCMSSignature = function verifyCMSSignature(CMSSignature, certificate, buffer) {
    /*
     * CMSSignature: base64
     * certificate: base64
     * buffer: byteArray
     * Returns object user: boolean, indicatin if signature is valid
     */
    // signature
    var clearCMSSignature = CMSSignature.replace(/(-----(BEGIN|END)( NEW)? CMS-----|\n)/g, '');
    var CMSBuffer = stringToArrayBuffer(window.atob(clearCMSSignature));
    var asn1 = org.pkijs.fromBER(CMSBuffer);
    var cms_content_simpl = new org.pkijs.simpl.CMS_CONTENT_INFO({
        schema: asn1.result
    });
    var cms_signed_simpl = new org.pkijs.simpl.CMS_SIGNED_DATA({
        schema: cms_content_simpl.content
    });

    // certificate
    var clearCert = certificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, '');
    var certBuffer = stringToArrayBuffer(window.atob(clearCert));
    asn1 = org.pkijs.fromBER(certBuffer);
    var cert_simpl = new org.pkijs.simpl.CERT({
        schema: asn1.result
    });

    var trustedCertificates = [];
    trustedCertificates.push(cert_simpl);
    return cms_signed_simpl.verify({
        signer: 0,
        trusted_certs: trustedCertificates,
        checkChain: false,
        data: buffer
    }).then(
        function(result) {
            return result;
        },
        function(error) {
            console.error('Signature verification failed: ', error);
        }
    );
}
