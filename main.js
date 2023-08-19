// Requires
"use strict";
const crypto = require("crypto")["webcrypto"];
const Ed25519 = require("./Ed25519-0.0.22.js");
const X25519 = require("./X25519-0.0.23.js");
const Common = require("./common.js");
const Base58 = require("./base58.js");
const Base64 = require("./base64.js-3.7.5.js");
const chacha = require("./ChaCha-2.1.0.js");


// Constants
const HEADER_VERSION_LINE = "age-encryption.org/v1";
const HEADER_STANZA_LINE_PREFIX = "->";
const HEADER_MAC_LINE_PREFIX = "---";
const STANZA_WRAPPED_BODY_LENGTH = 64;
const BASE64_PADDING_CHARACTER = "=";
const X25519_RECIPIENT_STANZA_NUMBER_OF_ARGUMENTS = 2;
const X25519_RECIPIENT_STANZA_FIRST_ARGUMENT = "X25519";
const SCRYPT_RECIPIENT_STANZA_FIRST_ARGUMENT = "scrypt";
const X25519_PUBLIC_KEY_LENGTH = 32;
const X25519_SECRET_KEY_LENGTH = 32;
const CHACHA20_POLY1305_TAG_LENGTH = 16;
const CHACHA20_POLY1305_NONCE_LENGTH = 12;
const FILE_KEY_LENGTH = 16;
const MAC_LENGTH = 32;
const PAYLOAD_NONCE_LENGTH = 16;
const MAXIMUM_PAYLOAD_CHUNK_SIZE = Math.pow(2, 16);
const ED25519_SECRET_KEY_LENGTH = 32;


// Supporting function implementation

// Is printable character
function isPrintableCharacter(character) {
	return character >= " ".charCodeAt(0) && character <= "~".charCodeAt(0);
}

// Age encrypt
async function ageEncrypt(data, receiverEd25519PublicKey) {

	do {
	
		var ephemeralEd25519SecretKey = crypto.getRandomValues(new Uint8Array(ED25519_SECRET_KEY_LENGTH));
		var ephemeralX25519SecretKey = X25519.secretKeyFromEd25519SecretKey(ephemeralEd25519SecretKey);
		var ephemeralEd25519PublicKey = Ed25519.publicKeyFromSecretKey(ephemeralEd25519SecretKey);
		var ephemeralX25519PublicKey = X25519.publicKeyFromEd25519PublicKey(ephemeralEd25519PublicKey);
		
		var receiverX25519PublicKey = X25519.publicKeyFromEd25519PublicKey(receiverEd25519PublicKey);
		
		if(Common.arraysAreEqual(receiverX25519PublicKey, (new Uint8Array(X25519_PUBLIC_KEY_LENGTH)).fill(0))) {
			return false;
		}
		
		var sharedSecret = X25519.sharedSecretKeyFromSecretKeyAndPublicKey(ephemeralX25519SecretKey, receiverX25519PublicKey);
	
	} while(Common.arraysAreEqual(sharedSecret, (new Uint8Array(X25519_SECRET_KEY_LENGTH)).fill(0)));
	
	var salt = Common.mergeArrays([ephemeralX25519PublicKey, receiverX25519PublicKey]);
			
	var sharedSecretBase = await crypto.subtle.importKey("raw", sharedSecret, {
		name: "HKDF"
	}, false, ["deriveBits"]);
	
	var wrapKey = new Uint8Array(await crypto.subtle.deriveBits({
		name: "HKDF",
		hash: "SHA-256",
		salt,
		info: (new TextEncoder()).encode("age-encryption.org/v1/X25519")
	}, sharedSecretBase, 256));
	
	var cipher = chacha.createCipher(wrapKey, (new Uint8Array(CHACHA20_POLY1305_NONCE_LENGTH)).fill(0));
	
	var fileKey = crypto.getRandomValues(new Uint8Array(FILE_KEY_LENGTH));
	
	try {
		var encryptedFileKey = cipher.update(fileKey);
		encryptedFileKey = Common.mergeArrays([encryptedFileKey, cipher.final()]);
	}
	catch(error) {
		return false;
	}
	
	encryptedFileKey = Common.mergeArrays([encryptedFileKey, cipher.getAuthTag()]);
	
	var ageHeader = `${HEADER_VERSION_LINE}\n` +
	`${HEADER_STANZA_LINE_PREFIX} ${X25519_RECIPIENT_STANZA_FIRST_ARGUMENT} ${Base64.fromUint8Array(ephemeralX25519PublicKey).replace(/=+$/u, "")}\n` +
	`${Base64.fromUint8Array(encryptedFileKey).replace(/=+$/u, "")}\n` +
	`${HEADER_MAC_LINE_PREFIX}`;
	
	var fileKeyBase = await crypto.subtle.importKey("raw", fileKey, {
		name: "HKDF"
	}, false, ["deriveKey", "deriveBits"]);
	
	var hmacKey = await crypto.subtle.deriveKey({
		name: "HKDF",
		hash: "SHA-256",
		salt: new Uint8Array([]),
		info: (new TextEncoder()).encode("header")
	}, fileKeyBase, {
		name: "HMAC",
		hash: "SHA-256",
		length: 256
	}, false , ["sign"]);
	
	var mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, (new TextEncoder()).encode(ageHeader)));
	
	ageHeader += ` ${Base64.fromUint8Array(mac).replace(/=+$/u, "")}\n`;
	
	var nonce = crypto.getRandomValues(new Uint8Array(PAYLOAD_NONCE_LENGTH));
	
	var payloadKey = new Uint8Array(await crypto.subtle.deriveBits({
		name: "HKDF",
		hash: "SHA-256",
		salt: nonce,
		info: (new TextEncoder()).encode("payload")
	}, fileKeyBase, 256));
	
	var agePayload = nonce;
	for(var i = 0; i < Math.max(Math.ceil(data.length / MAXIMUM_PAYLOAD_CHUNK_SIZE), 1); ++i) {
	
		var chunk = data.subarray(i * MAXIMUM_PAYLOAD_CHUNK_SIZE, (i + 1) * MAXIMUM_PAYLOAD_CHUNK_SIZE);
		
		var cipher = chacha.createCipher(payloadKey, new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, i, (i === Math.max(Math.ceil(data.length / MAXIMUM_PAYLOAD_CHUNK_SIZE), 1) - 1) ? 0x01 : 0x00]));
		
		try {
			if(chunk.length !== 0) {
				agePayload = Common.mergeArrays([agePayload, cipher.update(chunk)]);
			}
			
			agePayload = Common.mergeArrays([agePayload, cipher.final()]);
		}
		catch(error) {
			return false;
		}
		
		agePayload = Common.mergeArrays([agePayload, cipher.getAuthTag()]);
	}
	
	return Common.mergeArrays([(new TextEncoder()).encode(ageHeader), agePayload]);
}

// Age decrypt
async function ageDecrypt(ageFile, receiverEd25519SecretKey) {

	var endOfHeaderIndex = -1;
	for(var newlineIndex = ageFile.indexOf("\n".charCodeAt(0)); newlineIndex !== -1; newlineIndex = ageFile.indexOf("\n".charCodeAt(0), newlineIndex + "\n".length)) {
		if(Common.arraysAreEqual(ageFile.subarray(newlineIndex, newlineIndex + `\n${HEADER_MAC_LINE_PREFIX} `.length), (new TextEncoder()).encode(`\n${HEADER_MAC_LINE_PREFIX} `))) {
			endOfHeaderIndex = ageFile.indexOf("\n".charCodeAt(0), newlineIndex + `\n${HEADER_MAC_LINE_PREFIX} `.length);
			break;
		}
	}

	if(endOfHeaderIndex === -1) {
		return false;
	}
	
	for(var i = 0; i < endOfHeaderIndex; ++i) {
		if(!isPrintableCharacter(ageFile[i]) && ageFile[i] !== "\n".charCodeAt(0)) {
			return false;
		}
	}
	
	var ageHeader = (new TextDecoder()).decode(ageFile.subarray(0, endOfHeaderIndex + "\n".length));
	var agePayload = ageFile.subarray(endOfHeaderIndex + "\n".length);
	
	if(!ageHeader.startsWith(`${HEADER_VERSION_LINE}\n${HEADER_STANZA_LINE_PREFIX} `)) {
		return false;
	}
	
	var stanzas = [];
	var startOfLine = `${HEADER_VERSION_LINE}\n`.length;
	while(ageHeader.substring(startOfLine, startOfLine + `${HEADER_STANZA_LINE_PREFIX} `.length) === `${HEADER_STANZA_LINE_PREFIX} `) {
	
		var endOfLine = ageHeader.indexOf("\n", startOfLine);
		if(endOfLine === -1) {
			return false;
		}
		
		var stanzaArguments = ageHeader.substring(startOfLine + `${HEADER_STANZA_LINE_PREFIX} `.length, endOfLine).split(" ");
		if(stanzaArguments.length === 0) {
			return false;
		}
		
		if(stanzaArguments[0] === SCRYPT_RECIPIENT_STANZA_FIRST_ARGUMENT) {
			return false;
		}
		
		var stanzaBody = "";
		for(startOfLine = endOfLine + "\n".length;; startOfLine = endOfLine + "\n".length) {
		
			endOfLine = ageHeader.indexOf("\n", startOfLine);
			if(endOfLine === -1) {
				return false;
			}
			
			stanzaBody += ageHeader.substring(startOfLine, endOfLine);
			
			if(endOfLine - startOfLine > STANZA_WRAPPED_BODY_LENGTH) {
				return false;
			}
			else if(endOfLine - startOfLine < STANZA_WRAPPED_BODY_LENGTH) {
				startOfLine = endOfLine + "\n".length;
				break;
			}
		}
		
		if(stanzaBody.endsWith(BASE64_PADDING_CHARACTER)) {
			return false;
		}
		
		if(stanzaArguments.length === X25519_RECIPIENT_STANZA_NUMBER_OF_ARGUMENTS && stanzaArguments[0] === X25519_RECIPIENT_STANZA_FIRST_ARGUMENT) {
		
			if(stanzaArguments[1].endsWith(BASE64_PADDING_CHARACTER)) {
				continue;
			}
			
			try {
				var ephemeralX25519PublicKey = Base64.toUint8Array(stanzaArguments[1]);
				var encryptedFileKey = Base64.toUint8Array(stanzaBody);
			}
			catch(error) {
				continue;
			}
			
			if(ephemeralX25519PublicKey.length === X25519_PUBLIC_KEY_LENGTH && encryptedFileKey.length === FILE_KEY_LENGTH + CHACHA20_POLY1305_TAG_LENGTH) {
			
				stanzas.push({
					ephemeralX25519PublicKey,
					encryptedFileKey
				});
			}
		}
	}
	
	if(ageHeader.substring(startOfLine, startOfLine + `${HEADER_MAC_LINE_PREFIX} `.length) !== `${HEADER_MAC_LINE_PREFIX} `) {
		return false;
	}
	
	var endOfLine = ageHeader.indexOf("\n", startOfLine);
	if(endOfLine === -1 || endOfLine + "\n".length !== ageHeader.length) {
		return false;
	}
	
	var encodedMac = ageHeader.substring(startOfLine + `${HEADER_MAC_LINE_PREFIX} `.length, endOfLine);
	
	if(encodedMac.endsWith(BASE64_PADDING_CHARACTER)) {
		return false;
	}
	
	try {
		var expectedMac = Base64.toUint8Array(encodedMac);
	}
	catch(error) {
		return false;
	}
	
	if(expectedMac.length !== MAC_LENGTH) {
		return false;
	}
	
	var receiverX25519SecretKey = X25519.secretKeyFromEd25519SecretKey(receiverEd25519SecretKey);
	var receiverEd25519PublicKey = Ed25519.publicKeyFromSecretKey(receiverEd25519SecretKey);
	var receiverX25519PublicKey = X25519.publicKeyFromEd25519PublicKey(receiverEd25519PublicKey);
	
	var fileKey = null;
	for(const stanza of stanzas) {
	
		var sharedSecret = X25519.sharedSecretKeyFromSecretKeyAndPublicKey(receiverX25519SecretKey, stanza.ephemeralX25519PublicKey);
		if(!Common.arraysAreEqual(sharedSecret, (new Uint8Array(X25519_SECRET_KEY_LENGTH)).fill(0))) {
		
			var salt = Common.mergeArrays([stanza.ephemeralX25519PublicKey, receiverX25519PublicKey]);
			
			var sharedSecretBase = await crypto.subtle.importKey("raw", sharedSecret, {
				name: "HKDF"
			}, false, ["deriveBits"]);
			
			var wrapKey = new Uint8Array(await crypto.subtle.deriveBits({
				name: "HKDF",
				hash: "SHA-256",
				salt,
				info: (new TextEncoder()).encode("age-encryption.org/v1/X25519")
			}, sharedSecretBase, 256));
			
			var decipher = chacha.createDecipher(wrapKey, (new Uint8Array(CHACHA20_POLY1305_NONCE_LENGTH)).fill(0));
			decipher.setAuthTag(stanza.encryptedFileKey.subarray(stanza.encryptedFileKey.length - CHACHA20_POLY1305_TAG_LENGTH));
			
			try {
				fileKey = decipher.update(stanza.encryptedFileKey.subarray(0, stanza.encryptedFileKey.length - CHACHA20_POLY1305_TAG_LENGTH));
				fileKey = Common.mergeArrays([fileKey, decipher.final()]);
			}
			catch(error) {
				fileKey = null;
				continue;
			}
			
			break;
		}
	}
	
	if(fileKey === null) {
		return false;
	}
	
	var fileKeyBase = await crypto.subtle.importKey("raw", fileKey, {
		name: "HKDF"
	}, false, ["deriveKey", "deriveBits"]);
	
	var hmacKey = await crypto.subtle.deriveKey({
		name: "HKDF",
		hash: "SHA-256",
		salt: new Uint8Array([]),
		info: (new TextEncoder()).encode("header")
	}, fileKeyBase, {
		name: "HMAC",
		hash: "SHA-256",
		length: 256
	}, false , ["sign"]);
	
	var mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, (new TextEncoder()).encode(ageHeader.substring(0, startOfLine + HEADER_MAC_LINE_PREFIX.length))));
	if(!Common.arraysAreEqual(mac, expectedMac)) {
		return false;
	}
	
	if(agePayload.length < PAYLOAD_NONCE_LENGTH + CHACHA20_POLY1305_TAG_LENGTH) {
		return false;
	}

	var nonce = agePayload.subarray(0, PAYLOAD_NONCE_LENGTH);
	
	var payloadKey = new Uint8Array(await crypto.subtle.deriveBits({
		name: "HKDF",
		hash: "SHA-256",
		salt: nonce,
		info: (new TextEncoder()).encode("payload")
	}, fileKeyBase, 256));
	
	var data = [];
	for(var i = 0; i < Math.ceil((agePayload.length - PAYLOAD_NONCE_LENGTH) / (MAXIMUM_PAYLOAD_CHUNK_SIZE + CHACHA20_POLY1305_TAG_LENGTH)); ++i) {
	
		var chunk = agePayload.subarray(PAYLOAD_NONCE_LENGTH + i * (MAXIMUM_PAYLOAD_CHUNK_SIZE + CHACHA20_POLY1305_TAG_LENGTH), PAYLOAD_NONCE_LENGTH + (i + 1) * (MAXIMUM_PAYLOAD_CHUNK_SIZE + CHACHA20_POLY1305_TAG_LENGTH));
		
		if(chunk.length < CHACHA20_POLY1305_TAG_LENGTH) {
			return false;
		}
		else if(chunk.length === CHACHA20_POLY1305_TAG_LENGTH && i !== 0) {
			return false;
		}
		
		var decipher = chacha.createDecipher(payloadKey, new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, i, (i === Math.ceil((agePayload.length - PAYLOAD_NONCE_LENGTH) / (MAXIMUM_PAYLOAD_CHUNK_SIZE + CHACHA20_POLY1305_TAG_LENGTH)) - 1) ? 0x01 : 0x00]));
		decipher.setAuthTag(chunk.subarray(chunk.length - CHACHA20_POLY1305_TAG_LENGTH));
		
		try {
			if(chunk.length > CHACHA20_POLY1305_TAG_LENGTH) {
				data = Common.mergeArrays([data, decipher.update(chunk.subarray(0, chunk.length - CHACHA20_POLY1305_TAG_LENGTH))]);
			}
			
			data = Common.mergeArrays([data, decipher.final()]);
		}
		catch(error) {
			return false;
		}
	}
	
	return data;
}


// Main function
(async function() {

	await Ed25519.initialize();
	await X25519.initialize();
	
	var receiverEd25519SecretKey = Common.fromHexString("e68ecb10604b1ae91cd28bebdff817a5587f67005119fc9d8384ee15e5de1ccb");
	var receiverEd25519PublicKey = Ed25519.publicKeyFromSecretKey(receiverEd25519SecretKey);

	var slatepack = "BEGINSLATEPACK. 3u4xRAp95oEt8Vb j1hLTs8kgHBn6kU ZKd76wRFpVqsP1A ZzagCLb7Fm2Z5bP pYi8jXaLVJgkrCj hE5mq38WCtDUdU5 8sHK2YsWMXvJvhw Qrwx7zDHy5n7Bw5 ufzjpn3UpKoJ4tG 8qqGxDoLGeYp3yK LZN6GYKZCz1G49n PYwiE6fkmp8Uf7n 4QjSqAhWNNKFf8Q kWMBTU6UzS2SfUh wnPXnEwLs1TdZdw ssoDYeovtSXvgvE LxfQoc9YsLJAcet zsXQK6xX3ekbUHh 4hbZDkoEse6yTYy jBY7xvYjAsSTMwi BZkNYE25M2ZNJCb g76a71EUCk9RuGp rjCpVU1gpKT1hLm 6afDUgPaQTg88Ys oKby9Gf98h7Aq7L EEzTVgomXNjZCgc H5kqrZBra64E212 5Tmimg29tWYHqAC e6yxq2vqLqdqwbm Mh3R2gBzGfuaa4s XuSfs2R6kfWTfbY bqY3eLPLVw6JSKZ cBFCfC34kK6a6Y6 xwk9qLcuBxmhvj4 AFHUHfzYx5Dk54E wkqZNxg62ixMrrr coBBsf2vdHZGWK6 H49aKT2wvgnDwvB DnXu9jSgd74D17P 6q1LwEQUpyhhr9o 8VabGrVsgjycD6x CBYSRXuLZxteH6H zi5LM4w2935s42q uYLoS7sp9EHpNcp igJcdQ1hnELux7f NXTs9dNdRwXfvjL 5RfZ9XxyCYEEpXB TZNPaXEcPnD2XnC WWgQaBCybi6kvQe 8vwJpuWXTwpdAcX HACGeQDqV7RgVrd DU8NKMjhac8s6n2 xmQSEM3qmf. ENDSLATEPACK.";
	var payload = slatepack.substring("BEGINSLATEPACK. ".length, slatepack.length - ". ENDSLATEPACK.".length).replace(/[ \n\r]/ug, "");
	var decodedPayload = Base58.decode(payload);
	var ageFile = decodedPayload.subarray(21);
	
	// Test decrypting a Slatepack's age file
	console.log((new TextDecoder()).decode(await ageDecrypt(ageFile, receiverEd25519SecretKey)));
	
	// Test age encrypting and decrypting arbitrary data
	console.log(await ageDecrypt(await ageEncrypt(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]), receiverEd25519PublicKey), receiverEd25519SecretKey));
})();
