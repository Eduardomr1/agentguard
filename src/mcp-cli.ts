#!/usr/bin/env node
import { AgentGuardMcpServer } from "./mcp.js";

const server = new AgentGuardMcpServer();
server.start();

process.on("SIGINT", () => {
  server.stop();
  process.exit(0);
});

process.on("SIGTERM", () => {
  server.stop();
  process.exit(0);
});
