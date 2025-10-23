import { defineConfig } from "drizzle-kit";

export default defineConfig({
  out: "./migrations",
  schema: "./shared/schema.ts",
  dialect: "postgresql",
  dbCredentials: {
    url: "postgresql://ride_to_go_owner:lVFfQ26XGHBb@ep-withered-hat-a195u9hi-pooler.ap-southeast-1.aws.neon.tech/cryptoshield?sslmode=require&channel_binding=require",
  },
});
