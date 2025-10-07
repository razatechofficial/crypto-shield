import * as dotenv from "dotenv";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// Load environment variables from .env file
dotenv.config({ path: resolve(__dirname, "../.env") });

// Validate required environment variables
const requiredEnvVars = ["DATABASE_URL"];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}

export const config = {
  database: {
    url: process.env.DATABASE_URL,
  },
  server: {
    port: parseInt(process.env.PORT || "3000", 10),
    nodeEnv: process.env.NODE_ENV || "development",
  },
  security: {
    sessionSecret:
      process.env.SESSION_SECRET || "default-secret-key-change-this",
  },
  telemetry: {
    enabled: process.env.AVEROX_TELEMETRY === "enabled",
    traceEnabled: process.env.OTEL_TRACE_ENABLED === "true",
  },
};
