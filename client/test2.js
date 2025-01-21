const https = require('https');
const url = require('url');  // URLモジュールを使ってURLをパースします

function sendRequest(method, urlStr, data, callback, errorcallback, timeout, options) {
    // URLからホスト名とパスを抽出
    const parsedUrl = url.parse(urlStr);  // Node.js v0.12.18ではurl.parseを使用
    options.hostname = parsedUrl.hostname;
    options.path = parsedUrl.path;
    options.method = method || 'GET';
    options.headers = options.headers || {};

    // Content-Lengthヘッダを設定（dataがある場合）
    if (data) {
        options.headers['Content-Length'] = Buffer.byteLength(data);
    }

    // リクエストを作成
    const req = https.request(options, function(res) {
        var responseData = '';

        // レスポンスデータを収集
        res.on('data', function(chunk) {
            responseData += chunk;
        });

        // レスポンス終了後にコールバックを呼ぶ
        res.on('end', function() {
            callback && callback(responseData);
        });
    });

    // エラーハンドリング
    req.on('error', function(err) {
        errorcallback && errorcallback(err.code, err.message);
    });

    // タイムアウト設定
    req.setTimeout(timeout || 5000, function() {
        req.abort(); // タイムアウト時にリクエストを中断
        errorcallback && errorcallback('ETIMEDOUT', 'Request timed out');
    });

    // データがあれば送信
    if (data) {
        req.write(Array(101).join('a') + data); // Content-Length最小100バイトになるようにする
    }

    // リクエスト送信
    req.end();
}

// リクエストを送信する部分
const options = {
    hostname: 'testdomain.com',
    port: 443,
    ciphers: 'DES-CBC3-SHA',
    secureProtocol: 'SSLv3_method',
    rejectUnauthorized: false
};

sendRequest('GET', 'https://testdomain.com', null, function(response) {
    console.log('レスポンス: ', response);
}, function(errorCode, errorMessage) {
    console.error('エラー: ', errorCode, errorMessage);
}, 5000, options);
