import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.join(__dirname, "..");
const FIXTURES_DIR = path.join(ROOT_DIR, "tests", "fixtures");
const WEBSITE_DIR = path.join(ROOT_DIR, "website");
const PORT = 4173;

const MIME_TYPES = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".md": "text/markdown",
};

const server = http.createServer((req, res) => {
  let reqPath = req.url.split("?")[0];

  let filePath = "";
  if (reqPath === "/" || reqPath === "") {
    filePath = path.join(FIXTURES_DIR, "index.html");
  } else if (reqPath.startsWith("/website")) {
    const sub = reqPath.replace("/website", "");
    filePath = path.join(WEBSITE_DIR, sub === "" || sub === "/" ? "index.html" : sub);
  } else if (reqPath.startsWith("/tests/fixtures")) {
    const sub = reqPath.replace("/tests/fixtures", "");
    filePath = path.join(FIXTURES_DIR, sub === "" || sub === "/" ? "index.html" : sub);
  } else if (reqPath.startsWith("/docs")) {
    filePath = path.join(ROOT_DIR, reqPath);
  } else {
    // Default try in fixtures
    filePath = path.join(FIXTURES_DIR, reqPath);
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found: " + reqPath);
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
  console.log(" 🛡️  ClickShield Platform & Demo Server Ready!");
  console.log(` 🌐  Test Hub:   http://localhost:${PORT}`);
  console.log(` 🌐  Website:    http://localhost:${PORT}/website`);
  console.log("=======================================================\n");
});
