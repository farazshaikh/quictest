import { QUICServer } from "@matrixai/quic";
import Logger, { formatting, LogLevel, StreamHandler } from "@matrixai/logger";
import {
  generateKeyHMAC,
  generateRSAKey,
  generateRSAX509,
  keyPairRSAToPEM,
  ServerCryptoOps,
} from "./x509crypt";

let server: QUICServer | undefined;

async function startServer() {
  const logger = new Logger("N1TSRollman", LogLevel.WARN, [
    new StreamHandler(
      formatting
        .format`${formatting.level}:${formatting.keys}:${formatting.msg}`,
    ),
  ]);

  const rsaKeys = await generateRSAKey();
  const certRSAPEM = await generateRSAX509(rsaKeys);
  const rsaKeysPem = await keyPairRSAToPEM(rsaKeys);

  /* Build HMAC */
  const hmacKey = await generateKeyHMAC();
  server = new QUICServer({
    crypto: {
      key: hmacKey,
      ops: ServerCryptoOps,
    },
    config: {
      key: rsaKeysPem.privateKey,
      cert: certRSAPEM,
    },
    logger: logger.getChild("QUICServer"),
  });

  await server.start({
    port: 3090,
  });
  console.log(server.port);
}

async function main(mode: "server" | "client" = "server") {
  if (mode === "server") {
    await startServer();
  } else {
    console.log("Client behavior not implemented yet.");
  }
}
process.on("SIGINT", async () => {
  if (server) {
    console.log("Shutting down server...");
    await server.stop();
    console.log("Server stopped.");
    process.exit(0);
  }
});

const mode: "server" | "client" = process.argv[2] === "client"
  ? "client"
  : "server";
main(mode);
