/**
 * @file x509crypt.ts
 * @description
 * This file provides helper functions for generating self-signed X.509 certificates using RSA keys.
 * It includes functions for generating RSA key pairs, converting them to PEM format, and creating
 * self-signed certificates. This is intended as a helper for specific use cases and not as a
 * generic library.
 *
 * @module x509crypt
 *
 * @example
 * ```typescript
 * import { generateRSAKey, generateRSAX509, keyPairRSAToPEM } from './x509crypt';
 *
 * async function main() {
 *   const keys = await generateRSAKey();
 *   const cert = await generateRSAX509(keys);
 *   const pemKeys = await keyPairRSAToPEM(keys);
 *   console.log(cert);
 *   console.log(pemKeys.publicKey);
 *   console.log(pemKeys.privateKey);
 * }
 *
 * main();
 * ```
 */
import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";
import { ServerCryptoOps } from "@matrixai/quic";
const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

/* Generate RSA keys and Certificate */
const RSA_ALG = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 2048,
};

/*
 * HMAC
 */
async function generateKeyHMAC(): Promise<ArrayBuffer> {
    const cryptoKey = await crypto.subtle.generateKey(
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
    );
    const key = await crypto.subtle.exportKey("raw", cryptoKey);
    return key;
}

async function signHMAC(key: ArrayBuffer, data: ArrayBuffer) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
    );
    return crypto.subtle.sign("HMAC", cryptoKey, data);
}

async function verifyHMAC(
    key: ArrayBuffer,
    data: ArrayBuffer,
    sig: ArrayBuffer,
) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
    );
    return crypto.subtle.verify("HMAC", cryptoKey, sig, data);
}

const ServerCryptoOps: ServerCryptoOps = {
    sign: signHMAC,
    verify: verifyHMAC,
};

/**
 * Converts an RSA key pair to PEM format.
 *
 * @param {CryptoKeyPair} param0 - An object containing the RSA public and private keys.
 * @param {CryptoKey} param0.publicKey - The RSA public key.
 * @param {CryptoKey} param0.privateKey - The RSA private key.
 * @returns {Promise<{ publicKey: string; privateKey: string }>} A promise that resolves to an object containing the PEM-formatted public and private keys.
 */
async function keyPairRSAToPEM({
    publicKey,
    privateKey,
}: CryptoKeyPair): Promise<{
    publicKey: string;
    privateKey: string;
}> {
    const publicKeySPKI = await crypto.subtle.exportKey("spki", publicKey);
    const publicKeySPKIBuffer = Buffer.from(publicKeySPKI);
    const publicKeyPEMBody = publicKeySPKIBuffer
        .toString("base64")
        .replace(/(.{64})/g, "$1\n")
        .trimEnd() + "\n";
    const publicKeyPEM =
        `-----BEGIN PUBLIC KEY-----\n${publicKeyPEMBody}\n-----END PUBLIC KEY-----\n`;
    const privateKeyPKCS8 = await crypto.subtle.exportKey("pkcs8", privateKey);
    const privateKeyPKCS8Buffer = Buffer.from(privateKeyPKCS8);
    const privateKeyPEMBody = privateKeyPKCS8Buffer
        .toString("base64")
        .replace(/(.{64})/g, "$1\n")
        .trimEnd() + "\n";
    const privateKeyPEM =
        `-----BEGIN PRIVATE KEY-----\n${privateKeyPEMBody}-----END PRIVATE KEY-----\n`;
    return {
        publicKey: publicKeyPEM,
        privateKey: privateKeyPEM,
    };
}

/**
 * Generates a self-signed X.509 certificate using RSA keys.
 *
 * @param {CryptoKeyPair} keys - The RSA key pair to use for generating the certificate.
 * @returns {Promise<string>} A promise that resolves to the PEM-encoded X.509 certificate.
 *
 * @throws {Error} If the certificate generation fails.
 *
 * @example
 * ```typescript
 * const keys = await crypto.subtle.generateKey(
 *   {
 *     name: "RSASSA-PKCS1-v1_5",
 *     modulusLength: 2048,
 *     publicExponent: new Uint8Array([1, 0, 1]),
 *     hash: "SHA-256",
 *   },
 *   true,
 *   ["sign", "verify"]
 * );
 * const cert = await generateRSAX509(keys);
 * console.log(cert);
 * ```
 */
async function generateRSAX509(
    keys: CryptoKeyPair,
): Promise<string> {
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: "CN=Test",
        notBefore: new Date("2025/01/01"),
        notAfter: new Date("2026/01/02"),
        signingAlgorithm: RSA_ALG,
        keys,
        extensions: [
            new x509.BasicConstraintsExtension(true, 2, true),
            new x509.ExtendedKeyUsageExtension(
                ["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"],
                true,
            ),
            new x509.KeyUsagesExtension(
                x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
                true,
            ),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        ],
    });
    return cert.toString("pem");
}

/**
 * Generates an RSA key pair.
 *
 * This function uses the Web Cryptography API to generate a new RSA key pair
 * with the specified algorithm and key usages.
 *
 * @returns {Promise<CryptoKeyPair>} A promise that resolves to the generated RSA key pair.
 */
async function generateRSAKey(): Promise<CryptoKeyPair> {
    return await crypto.subtle.generateKey(RSA_ALG, true, [
        "sign",
        "verify",
    ]);
}

export {
    generateKeyHMAC,
    generateRSAKey,
    generateRSAX509,
    keyPairRSAToPEM,
    ServerCryptoOps,
};
