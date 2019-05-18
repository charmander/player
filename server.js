'use strict';

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const path = require('path');

const STORAGE_ROOT = path.join(__dirname, 'storage');
const STORAGE_REQUEST = /^\/storage\/(index|[a-p]{16})$/;

const indexSecret = fs.readFileSync(path.join(STORAGE_ROOT, 'index-secret'), 'ascii');
const expectedAuthorization = Buffer.from('index-secret ' + indexSecret, 'ascii');
const isExpectedAuthorization = authorization => {
	if (authorization === undefined) {
		return false;
	}

	const authorizationBytes = Buffer.from(authorization, 'ascii');

	return (
		authorizationBytes.length === expectedAuthorization.length &&
		crypto.timingSafeEqual(authorizationBytes, expectedAuthorization)
	);
};

class StaticResource {
	constructor(bytes, {contentType, cacheControl}) {
		this.bytes = bytes;
		this.contentType = contentType;
		this.cacheControl = cacheControl;
		this.etag =
			'"' +
			crypto.createHash('sha512')
				.update(bytes)
				.digest()
				.toString('base64', 0, 9) +
			'"';
	}

	respond(req, res) {
		res.setHeader('Cache-Control', this.cacheControl);
		res.setHeader('ETag', this.etag);

		if (req.headers['if-none-match'] === this.etag) {
			res.statusCode = 304;
			res.end();
			return;
		}

		res.setHeader('Content-Type', this.contentType);
		res.end(this.bytes);
	}
}

const viewerResource = new StaticResource(
	fs.readFileSync(path.join(__dirname, 'viewer.html')),
	{
		contentType: 'text/html;charset=utf-8',
		cacheControl: 'public, no-cache, max-age=2592000',
	}
);

const indexResource = new StaticResource(
	fs.readFileSync(path.join(STORAGE_ROOT, 'index')),
	{
		contentType: 'application/octet-stream',
		cacheControl: 'no-cache, max-age=2592000',
	}
);

const sendText = (res, text) => {
	res.setHeader('Content-Type', 'text/plain;charset=utf-8');
	res.end(text);
};

const respond = (req, res) => {
	res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
	res.setHeader('Strict-Transport-Security', 'max-age=31536000');

	if (req.headers.host !== expectedHost) {
		res.statusCode = 400;
		sendText(res, 'Unexpected Host header');
		return;
	}

	if (req.url === '/') {
		viewerResource.respond(req, res);
		return;
	}

	if (!isExpectedAuthorization(req.headers.authorization)) {
		res.statusCode = 401;
		res.setHeader('WWW-Authenticate', 'index-secret');
		sendText(res, 'Not authorized');
		return;
	}

	const match = STORAGE_REQUEST.exec(req.url);

	if (match === null) {
		res.statusCode = 404;
		sendText(res, 'Not found');
		return;
	}

	if (match[1] === 'index') {
		indexResource.respond(req, res);
	} else {
		const fileStream = fs.createReadStream(path.join(STORAGE_ROOT, match[1]));

		const openError = error => {
			fileStream.off('error', openError);
			fileStream.off('open', openSuccess);

			if (error.code === 'ENOENT') {
				res.statusCode = 404;
				sendText(res, 'Not found');
			} else {
				res.statusCode = 500;
				sendText(res, 'Server error');
			}

			console.error('Error serving %s: %O', req.url, error);
		};

		const openSuccess = () => {
			fileStream.off('error', openError);
			fileStream.off('open', openSuccess);

			res.setHeader('Cache-Control', 'max-age=31536000, immutable');
			res.setHeader('Content-Type', 'application/octet-stream');
			fileStream.pipe(res);

			fileStream.on('error', error => {
				fileStream.unpipe(res);
				res.destroy(error);
				console.error(error);
			});
		};

		fileStream.on('error', openError);
		fileStream.on('open', openSuccess);
	}
};

if (process.argv.length < 4 || process.argv.length > 5) {
	console.error('Usage: node server.js <host-header> <listen-port> [<listen-host>]');
	process.exitCode = 1;
	return;
}

const expectedHost = process.argv[2];
const listenPort = process.argv[3];
const listenHost = process.argv[4];

if (!listenPort.startsWith('/') && listenHost === undefined) {
	console.error('host required with port');
	process.exitCode = 1;
	return;
}

const server = https.createServer({
	cert: fs.readFileSync('cert.crt'),
	key: fs.readFileSync('cert.key'),
	ciphers: 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384',
	honorCipherOrder: false,
	minVersion: 'TLSv1.2',
}, respond);

server.listen(listenPort, listenHost, () => {
	console.log('listening at', server.address());
});
