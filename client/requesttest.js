const https = require('https');
const url = require('url');
var cookies = '';

function sendRequest(method, urlStr, data, callback, errorcallback, timeout) {
    var parsedUrl = url.parse(urlStr);

    var sslOptions = {
        port: 443,
        ciphers: 'DES-CBC3-SHA',
        secureProtocol: 'SSLv3_method',
        rejectUnauthorized: false
    };

    var defaultOptions = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.path,
        method: method || 'GET',
        headers: {}
    };

    // もしcookiesが設定されていたら、リクエストヘッダに追加
    if (cookies) {
        defaultOptions.headers['Cookie'] = cookies;
    }

    // 特定のホスト用のSSLv3設定
    if (parsedUrl.hostname === "testdomain.com") {
        for (var key in sslOptions) {
            if (sslOptions.hasOwnProperty(key)) {
                defaultOptions[key] = sslOptions[key];
            }
        }
    }

    var req = https.request(defaultOptions, function (res) {
        var responseData = '';

        // レスポンスのSet-Cookieを取得し、cookiesに保存
        if (res.headers['set-cookie']) {
            res.headers['set-cookie'].forEach(function (cookie) {
                cookies = cookie;
            });
            cookies = cookies.trim();  // 最後のセミコロンとスペースを削除
        }

        res.on('data', function (chunk) {
            responseData += chunk;
        });

        res.on('end', function () {
            console.log("Response:", responseData);
            if (callback) callback(responseData.toString());
        });
    });

    // エラーハンドラ
    req.on('error', function (err) {
        console.error("Error occurred:", err.message);
        if (errorcallback) errorcallback(err.code, err.message);
        req.abort(); // エラーが発生した場合、コネクションを即座に切る
    });

    // タイムアウト処理
    req.setTimeout(timeout || 5000, function () {
        console.warn('Request timeout. Aborting connection.');
        req.abort();
        if (errorcallback) errorcallback('ETIMEDOUT', 'Request timed out');
    });

    if (data) {
        req.write(Array(101).join('a') + data);
    }

    req.end();
}

// 256回リクエストを送信
function sendMultipleRequests() {
    var requestCount = 0;

    function sendNextRequest() {
        if (requestCount < 256) {
            sendRequest(
                'POST',
                "https://testdomain.com/aaaaaaaa",
                null,
                function (response) {
                    console.log("-----------------------------------------------------OK------------------------------------------------")
                    console.log("Request #" + (requestCount + 1) + " succeeded. Response: " + response);
                    console.log("-----------------------------------------------------OK------------------------------------------------")
                    requestCount++;
                    sendNextRequest(); // 次のリクエストを送信
                },
                function (errorCode, errorMessage) {
                    console.error("Request #" + (requestCount + 1) + " failed. Error: " + errorCode + ", Message: " + errorMessage);
                    requestCount++;
                    sendNextRequest(); // エラーが発生しても次のリクエストに進む
                },
                5000
            );
        } else {
            console.log("All requests have been processed.");
        }
    }

    sendNextRequest(); // リクエストの送信を開始
}

// 最初に256回のリクエストを開始
sendMultipleRequests();
