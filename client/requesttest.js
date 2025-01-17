const https = require('https');
const url = require('url');

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

// First request
sendRequest(
    'POST',
    "https://testdomain.com",
    null,
    function (response) {
        console.log("success first request");

        // After the first request is complete, wait 3 seconds before sending the second request
        setTimeout(function () {
            sendRequest(
                'POST',
                "https://testdomain.com",
                null,
                function (response) {
                    console.log("success second request")
                },
                function (errorCode, errorMessage) {
                    console.error("Error in second request:", errorCode, errorMessage);
                },
                5000
            );
        }, 3000);
    },
    function (errorCode, errorMessage) {
        console.error("Error in first request:", errorCode, errorMessage);
    },
    5000
);
