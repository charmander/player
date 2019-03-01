'use strict';

const assert = require('assert').strict;
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {inspect} = require('util');

const TOKEN_ENCODE_START = 'a'.charCodeAt(0);
const KEY_ALPHABET = 'abcdefghijklmnopqrstuvwxyz';
const KEY_LENGTH = 24;  // 112 bits
const ROUND_TO_NEAREST = 256 * 1024;  // 256 KiB
const ID_BYTES = 8;
const SORT_LOCALE = 'en';
const SORT_OPTIONS = {
	sensitivity: 'base',
	numeric: true,
};

const KEY_PATH = path.join(__dirname, 'secret-key');
const STORAGE_ROOT = path.join(__dirname, 'storage');
const TEMPORARY_ROOT = path.join(__dirname, 'temp');
const INDEX_PATH = path.join(STORAGE_ROOT, 'index');

const chomp = text =>
	text.endsWith('\n') ?
		text.endsWith('\r\n') ?
			text.slice(0, -2) :
			text.slice(0, -1) :
		text;

const tokenEncode = bytes => {
	const result = Buffer.alloc(2 * bytes.length);
	let i = 0;

	for (const byte of bytes) {
		result[i++] = (byte >>> 4) + TOKEN_ENCODE_START;
		result[i++] = (byte & 0xf) + TOKEN_ENCODE_START;
	}

	return result.toString('ascii');
};

const generateKey = () => {
	const ALPHABET_SIZE = BigInt(KEY_ALPHABET.length);
	const limit = ALPHABET_SIZE ** BigInt(KEY_LENGTH);
	const bitCount = Math.ceil(Math.log2(KEY_ALPHABET.length) * KEY_LENGTH);
	const byteCount = Math.ceil(bitCount / 8);
	const mask = 0xff >>> (8 - bitCount % 8) % 8;

	for (;;) {
		const bytes = crypto.randomBytes(byteCount);
		bytes[0] &= mask;

		let value = 0n;

		for (const byte of bytes) {
			value = 256n * value + BigInt(byte);
		}

		if (value < limit) {
			let result = '';

			for (let i = 0; i < KEY_LENGTH; i++) {
				result += KEY_ALPHABET.charAt(Number(value / ALPHABET_SIZE ** BigInt(i) % ALPHABET_SIZE));
			}

			return result;
		}
	}
};

const EMPTY = new Uint8Array();

class DerivableKey {
	constructor(id) {
		assert(Buffer.isBuffer(id) && id.length === 16);
		this._id = id;
	}

	derive(key) {
		const cipher = crypto.createCipheriv('AES-128-ECB', key, EMPTY);
		cipher.setAutoPadding(false);
		const derived = cipher.update(this._id);
		assert.equal(cipher.final().length, 0);
		return derived;
	}
}

const ENCRYPTION_KEY = new DerivableKey(Buffer.from('ed29594ac9e17e910c344f7a12f8979a', 'hex'));
const HMAC_KEY       = new DerivableKey(Buffer.from('5c2cbd044fbad7e79d61a91bb5a47108', 'hex'));
const ID_KEY         = new DerivableKey(Buffer.from('8eb0866b9d601c0c335a47ca6019a183', 'hex'));
const INDEX_SECRET   = new DerivableKey(Buffer.from('d19e547ec98c7d9ed9a80e8da01824e8', 'hex'));

const readKeySetSync = () => {
	let fd = null;
	let keyText;

	try {
		fd = fs.openSync(KEY_PATH, 'wx', 0o600);
	} catch (error) {
		if (error.code !== 'EEXIST') {
			throw error;
		}
	}

	if (fd === null) {
		keyText = chomp(fs.readFileSync(KEY_PATH, 'ascii'));

		if (keyText.length !== KEY_LENGTH || ![...keyText].every(c => KEY_ALPHABET.includes(c))) {
			throw new Error('Invalid key in ' + KEY_PATH);
		}
	} else {
		keyText = generateKey();
		console.error('Generated a new key:', keyText);
		fs.writeFileSync(fd, keyText, 'ascii');
		fs.closeSync(fd);
	}

	const keyBytes =
		crypto.createHash('sha256')
			.update(keyText)
			.digest().slice(0, 16);

	return {
		encryptionKey: ENCRYPTION_KEY.derive(keyBytes),
		hmacKey: HMAC_KEY.derive(keyBytes),
		idKey: ID_KEY.derive(keyBytes),
		indexSecret: INDEX_SECRET.derive(keyBytes),
	};
};

const getHmac = ({hmacKey}, iv, encrypted) =>
	crypto.createHmac('sha384', hmacKey)
		.update(iv)
		.update(encrypted)
		.digest();

const getId = ({idKey}, fileBytes) =>
	crypto.createHmac('sha512', idKey)
		.update(fileBytes)
		.digest().slice(0, ID_BYTES);

const getEncrypted = (keySet, fileBytes) => {
	const paddedSize = fileBytes.length + (ROUND_TO_NEAREST - (fileBytes.length % ROUND_TO_NEAREST)) % ROUND_TO_NEAREST;
	const encodedBytes = Buffer.alloc(4 + paddedSize);
	encodedBytes.writeUInt32LE(fileBytes.length, 0);
	fileBytes.copy(encodedBytes, 4);

	const iv = Buffer.alloc(16);
	crypto.randomFillSync(iv, 0, 12);  // high 12 bytes are nonce (2^32 blocks > 4 GB)

	const cipher = crypto.createCipheriv('AES-128-CTR', keySet.encryptionKey, iv);
	const encrypted = cipher.update(encodedBytes);
	assert.equal(cipher.final().length, 0);

	return {
		encrypted,
		iv,
		mac: getHmac(keySet, iv, encrypted),
		id: getId(keySet, fileBytes),
	};
};

const getDecrypted = (keySet, combinedBytes) => {
	assert(combinedBytes.length >= 16);

	const mac = combinedBytes.slice(0, 48);
	const iv = combinedBytes.slice(48, 64);
	const encrypted = combinedBytes.slice(64);

	const expectedMac = getHmac(keySet, iv, encrypted);

	if (!crypto.timingSafeEqual(mac, expectedMac)) {
		throw new Error('Invalid MAC');
	}

	const decipher = crypto.createDecipheriv('AES-128-CTR', keySet.encryptionKey, iv);
	const encodedBytes = decipher.update(encrypted);
	assert.equal(decipher.final().length, 0);

	const length = encodedBytes.readUInt32LE(0);

	if (length > encodedBytes.length - 4) {
		throw new Error('Invalid length');
	}

	return encodedBytes.slice(4, 4 + length);
};

const readIndexSync = (keySet, indexPath) => {
	const indexBytes = getDecrypted(keySet, fs.readFileSync(indexPath));
	const index = new Map();

	let offset = 0;

	while (offset < indexBytes.length) {
		const nameLength = indexBytes.readUInt8(offset);
		offset++;

		if (offset + nameLength + ID_BYTES > indexBytes.length) {
			throw new Error('Invalid length');
		}

		const name = indexBytes.toString('utf8', offset, offset + nameLength);
		offset += nameLength;

		const id = indexBytes.slice(offset, offset + ID_BYTES);
		offset += ID_BYTES;

		if (index.has(name)) {
			throw new Error('Duplicate name in index');
		}

		index.set(name, id);
	}

	return index;
};

const writeIndexSync = (keySet, index, indexPath) => {
	let indexSize = 0;
	const nameLengths = [];

	const sortedIndex = Array.from(index).sort(([a], [b]) => a.localeCompare(b, SORT_LOCALE, SORT_OPTIONS));

	for (const [name, id] of sortedIndex) {
		const nameLength = Buffer.byteLength(name, 'utf8');

		if (nameLength > 255) {
			throw new Error(`Name ${inspect(name)} too long`);
		}

		indexSize += 1 + nameLength + ID_BYTES;
		nameLengths.push(nameLength);
	}

	const indexBytes = Buffer.alloc(indexSize);
	let offset = 0;
	let i = 0;

	for (const [name, id] of sortedIndex) {
		const nameLength = nameLengths[i++];

		offset = indexBytes.writeUInt8(nameLength, offset);
		offset += indexBytes.write(name, offset, 'utf8');
		offset += id.copy(indexBytes, offset);
	}

	assert.equal(offset, indexSize);

	const {encrypted, iv, mac} = getEncrypted(keySet, indexBytes);

	const temporaryPath = getTemporaryPath();

	const fd = fs.openSync(temporaryPath, 'wx');
	fs.writeSync(fd, mac);
	fs.writeSync(fd, iv);
	fs.writeSync(fd, encrypted);
	fs.closeSync(fd);
	fs.renameSync(temporaryPath, indexPath);
};

const getTemporaryPath = () =>
	path.join(
		TEMPORARY_ROOT,
		crypto.randomBytes(6).toString('base64')
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
	);

const getStoragePath = id =>
	path.join(
		STORAGE_ROOT,
		tokenEncode(id)
	);

const mergeIndexSync = (keySet, index, newEntries) => {
	for (const [name, filePath] of newEntries) {
		const fileBytes = fs.readFileSync(filePath);
		const {encrypted, iv, mac, id} = getEncrypted(keySet, fileBytes);

		const temporaryPath = getTemporaryPath();
		const storagePath = getStoragePath(id);

		const fd = fs.openSync(temporaryPath, 'wx');
		fs.writeSync(fd, mac);
		fs.writeSync(fd, iv);
		fs.writeSync(fd, encrypted);
		fs.closeSync(fd);
		fs.renameSync(temporaryPath, storagePath);

		const existingId = index.get(name);

		if (existingId !== undefined && !id.equals(existingId)) {
			throw new Error(`Index already has different entry with name ${inspect(name)}`);
		}

		index.set(name, id);
	}
};

const keySet = readKeySetSync();

let index;

try {
	index = readIndexSync(keySet, INDEX_PATH);
} catch (error) {
	if (error.code !== 'ENOENT') {
		throw error;
	}

	index = new Map();
}

const toMerge = [];

for (let i = 2; i < process.argv.length; i++) {
	const importPath = process.argv[i];
	toMerge.push([path.basename(importPath, '.mp3'), importPath]);
}

mergeIndexSync(keySet, index, toMerge);

console.log(`Index contains ${index.size} file(s)`);

writeIndexSync(keySet, index, INDEX_PATH);

fs.writeFileSync(path.join(STORAGE_ROOT, 'index-secret'), tokenEncode(keySet.indexSecret));
