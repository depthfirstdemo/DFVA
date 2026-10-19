import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { createServer } from "http";
import { startScanWorker } from "./scanWorker";
import { initCredentials, scheduleMonthlyRotation } from "./credentials";
// VULN: Importing the GitHub integration module causes GITHUB_TOKEN (hardcoded
//       in server/github.ts) to be evaluated at module load time.
import { verifyGithubToken } from "./github";
// VULN: Importing the Google integration module causes GOOGLE_API_KEY (hardcoded
//       in server/google.ts) to be evaluated at module load time.
import { verifyGoogleKey } from "./google";

const app = express();
const httpServer = createServer(app);

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ extended: false }));

export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  console.log(`${formattedTime} [${source}] ${message}`);
}

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      // Credential endpoints intentionally return secrets to authenticated callers;
      // never duplicate those response bodies into application logs.
      if (capturedJsonResponse && !path.startsWith("/api/admin/credentials")) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  await registerRoutes(httpServer, app);
  startScanWorker();

  // Seed the four platform credentials on first boot, then arm the monthly scheduler.
  await initCredentials();
  scheduleMonthlyRotation();

  // Verify the GitHub integration token and log result to stdout.
  // VULN: verifyGithubToken() logs the raw token value regardless of success/failure.
  //       Any log aggregator, SIEM, or CI/CD platform that captures stdout gets the PAT.
  //       The outbound request to api.github.com also carries the token in the
  //       Authorization header — visible to any network proxy or load balancer.
  verifyGithubToken().catch(() => { /* network errors are non-fatal */ });

  // Verify the Google Cloud API key and log result to stdout.
  // VULN: verifyGoogleKey() logs the raw key value regardless of success/failure.
  //       Key appears in plaintext in any log aggregator, SIEM, or CI/CD platform
  //       that captures stdout.  Also sent as a URL query param to Discovery API,
  //       meaning it appears in GCP's own access logs on the other side of the wire.
  verifyGoogleKey().catch(() => { /* network errors are non-fatal */ });

  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    console.error("Internal Server Error:", err);

    if (res.headersSent) {
      return next(err);
    }

    return res.status(status).json({ message });
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (process.env.NODE_ENV === "production") {
    serveStatic(app);
  } else {
    const { setupVite } = await import("./vite");
    await setupVite(httpServer, app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || "5000", 10);
  httpServer.listen(
    {
      port,
      host: "0.0.0.0",
      reusePort: true,
    },
    () => {
      log(`serving on port ${port}`);
    },
  );
})();
