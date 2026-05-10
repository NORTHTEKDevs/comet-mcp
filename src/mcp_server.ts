import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import type { CometDriver } from "./comet_driver.js";

const ASK_INPUT = z.object({
  query: z.string().min(1, "query is required"),
  timeout_ms: z.number().int().positive().optional()
});

export function build_mcp_server(driver: CometDriver) {
  const server = new Server(
    { name: "comet-mcp", version: "0.0.1" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "ask_perplexity",
        description: "Ask Perplexity Comet a question and get the answer + cited sources. Uses your local Comet desktop browser via Ghost MCP. Synchronous; one query in flight at a time.",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", description: "The question to ask Perplexity." },
            timeout_ms: { type: "number", description: "Max ms to wait for the answer to finish streaming. Default 300000 (5 min)." }
          },
          required: ["query"]
        }
      }
    ]
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (req.params.name !== "ask_perplexity") {
      throw new Error(`unknown tool: ${req.params.name}`);
    }
    const args = ASK_INPUT.parse(req.params.arguments);
    const result = await driver.ask(args.query, args.timeout_ms);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
    };
  });

  return server;
}

export async function run_stdio(server: ReturnType<typeof build_mcp_server>) {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
