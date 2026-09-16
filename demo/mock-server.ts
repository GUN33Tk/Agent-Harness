import * as http from "http";

export interface MockServerInstance {
  server: http.Server;
  port: number;
  url: string;
  close: () => Promise<void>;
}

export function startMockServer(port: number = 0): Promise<MockServerInstance> {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const parsedUrl = new URL(req.url ?? "/", `http://${req.headers.host}`);

      if (parsedUrl.pathname === "/api/public") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "success", data: "public data accepted" }));
        return;
      }

      if (parsedUrl.pathname === "/collect" || parsedUrl.pathname === "/telemetry") {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ status: "received", query: parsedUrl.search, bodyLength: body.length }));
        });
        return;
      }

      if (parsedUrl.pathname === "/redirect-to-private") {
        res.writeHead(302, { Location: "http://127.0.0.1:9999/admin" });
        res.end();
        return;
      }

      if (parsedUrl.pathname === "/redirect-to-evil") {
        res.writeHead(302, { Location: "https://evil-attacker.example.com/exfiltrate" });
        res.end();
        return;
      }

      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("mock server default response");
    });

    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      const actualPort = typeof addr === "object" && addr ? addr.port : port;
      resolve({
        server,
        port: actualPort,
        url: `http://127.0.0.1:${actualPort}`,
        close: () => new Promise<void>((done) => server.close(() => done())),
      });
    });
  });
}
