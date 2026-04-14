import winston from "winston";
import { config } from "./config.js";

const { combine, timestamp, json, colorize, printf, errors } = winston.format;

const devFormat = combine(
  errors({ stack: true }),
  colorize(),
  timestamp({ format: "HH:mm:ss" }),
  printf(({ level, message, timestamp: ts, requestId, ...rest }) => {
    const meta = Object.keys(rest).length ? ` ${JSON.stringify(rest)}` : "";
    const rid = requestId ? ` [${requestId}]` : "";
    return `${ts}${rid} ${level}: ${message}${meta}`;
  })
);

const prodFormat = combine(errors({ stack: true }), timestamp(), json());

export const logger = winston.createLogger({
  level: config.NODE_ENV === "production" ? "info" : "debug",
  format: config.NODE_ENV === "production" ? prodFormat : devFormat,
  transports: [new winston.transports.Console()],
});

export default logger;
