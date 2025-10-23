import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "@shared/schema";
import { config } from "./config";

export const pool = new Pool({
  connectionString:
    "postgresql://ride_to_go_owner:lVFfQ26XGHBb@ep-withered-hat-a195u9hi-pooler.ap-southeast-1.aws.neon.tech/cryptoshield?sslmode=require&channel_binding=require",
});
export const db = drizzle(pool, { schema });
