import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";
import { QUICServer, ServerCryptoOps } from "@matrixai/quic";
import Logger, { formatting, LogLevel, StreamHandler } from "@matrixai/logger";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

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

/**
 * Generates RSA keypair
 */
async function generateKeyPairRSA(): Promise<{
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
}> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  return {
    publicKey: await crypto.subtle.exportKey("jwk", keyPair.publicKey),
    privateKey: await crypto.subtle.exportKey("jwk", keyPair.privateKey),
  };
}

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
 * Creates a self-signed X.509 certificate.
 *
 * This function generates a new RSA key pair and uses it to create a self-signed
 * X.509 certificate with specified parameters and extensions.
 *
 * @returns {Promise<x509.X509Certificate>} A promise that resolves to the generated X.509 certificate.
 *
 * @throws {Error} If there is an issue with the cryptographic operations or certificate generation.
 *
 * @example
 * ```typescript
 * createX509SelfSigned().then(cert => {
 *   console.log(cert.toString("pem"));
 * }).catch(err => {
 *   console.error("Failed to create certificate:", err);
 * });
 * ```
 */
async function createX509SelfSigned(
  alg: {
    name: string;
    hash: string;
    publicExponent: Uint8Array<ArrayBuffer>;
    modulusLength: number;
  },
  keys: CryptoKeyPair,
): Promise<x509.X509Certificate> {
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=Test",
    notBefore: new Date("2025/01/01"),
    notAfter: new Date("2026/01/02"),
    signingAlgorithm: alg,
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

  console.log(cert.toString("pem"));
  return cert;
}

async function main() {
  const logger = new Logger("N1TSRollman", LogLevel.WARN, [
    new StreamHandler(
      formatting
        .format`${formatting.level}:${formatting.keys}:${formatting.msg}`,
    ),
  ]);

  /* Generate RSA keys and Certificate */
  const alg = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 2048,
  };
  const keys: CryptoKeyPair = await crypto.subtle.generateKey(alg, true, [
    "sign",
    "verify",
  ]);
  const keyPairRSAPEM = await keyPairRSAToPEM(keys);
  const certRSA = await createX509SelfSigned(alg, keys);
  const certRSAPEM: string = certRSA.toString("pem");

  /* Build HMAC */
  const hmacKey = await generateKeyHMAC();
  const serverCryptoOps: ServerCryptoOps = {
    sign: signHMAC,
    verify: verifyHMAC,
  };

  const quicServer = new QUICServer({
    crypto: {
      key: hmacKey,
      ops: serverCryptoOps,
    },
    config: {
      key: keyPairRSAPEM.privateKey,
      cert: certRSAPEM,
    },
    logger: logger.getChild("QUICServer"),
  });

  await quicServer.start({
    port: 3090,
  });
  console.log(quicServer.port);
}

main();
