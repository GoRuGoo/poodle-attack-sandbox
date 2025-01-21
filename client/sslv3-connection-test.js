var https = require('https');

var options = {
    hostname: 'testdomain.com',
    port: 443,
    method: 'GET',
    ciphers: 'DES-CBC3-SHA',
    secureProtocol: 'SSLv3_method',
    rejectUnauthorized: false
}

var req = https.request(options, function (res) {
    console.log('Status code:', res.statusCode);
    res.on('data', function (chunk) {
        console.log('Body:', chunk.toString());
    });
});

req.on('error', function (e) {
    console.error('Request error:', e.message);
});

req.end();