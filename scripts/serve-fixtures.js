import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.join(__dirname, "..", "tests", "fixtures");
const PORT = 4173;

const MIME_TYPES = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

const server = http.createServer((req, res) => {
  let reqPath = req.url.split("?")[0];
  if (reqPath === "/" || reqPath === "") {
    reqPath = "/index.html";
  }

  const filePath = path.join(FIXTURES_DIR, reqPath);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Fixture not found: " + reqPath);
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "text/plain";

    res.writeHead(200, { "Content-Type": contentType });
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => {
  console.log("\n=======================================================");
  console.log(" 🛡️  ClickShield Security Testing & Demo Server Ready!");
  console.log(` 🌐  http://localhost:${PORT}`);
  console.log("=======================================================\n");
  console.log("Open http://localhost:" + PORT + " in Chrome with ClickShield enabled.");
  console.log("Press Ctrl+C to stop.\n");
});

