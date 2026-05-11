import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { createHash, randomUUID } from 'node:crypto';

interface AuthCode {
    codeChallenge: string;
    codeChallengeMethod: string;
    redirectUri: string;
    expiresAt: number;
}

type ServerCapabilities = {
    [key: string]: unknown;
    prompts?: { listChanged?: boolean };
    tools?: { listChanged?: boolean };
    resources?: { listChanged?: boolean };
};

interface Connection {
    id: string;
    transport: unknown;
    initialized: boolean;
}

export class McpServer {
    private server: Server;
    private app: Express;
    private connections: Map<string, Connection> = new Map();
    private nextConnectionId = 1;
    private capabilities: ServerCapabilities = {
        prompts: { listChanged: true },
        tools: { listChanged: true },
        resources: { listChanged: true }
    };

    constructor(name: string, version: string) {
        // Create server with proper initialization
        this.server = new Server(
            { name, version },
            { capabilities: this.capabilities }
        );

        // Initialize express app for SSE
        this.app = express();
        this.app.use(cors());
        this.app.use(express.json());

        // Note: The MCP SDK handles initialize/shutdown protocol methods automatically
        // No need to register custom handlers for these
    }

    private trackConnection(transport: unknown): void {
        const id = `conn_${this.nextConnectionId++}`;
        this.connections.set(id, { id, transport, initialized: false });
        console.error(`🔌 New connection established: ${id}`);
    }

    private untrackConnection(transport: unknown): void {
        for (const [id, conn] of this.connections.entries()) {
            if (conn.transport === transport) {
                this.connections.delete(id);
                console.error(`🔌 Connection closed: ${id}`);
                break;
            }
        }
    }

    getServer(): Server {
        return this.server;
    }

    getApp(): Express {
        return this.app;
    }

    getActiveConnections(): number {
        return this.connections.size;
    }

    async connectStdio(): Promise<void> {
        const transport = new StdioServerTransport();
        this.trackConnection(transport);
        try {
            await this.server.connect(transport);
        } catch (error) {
            this.untrackConnection(transport);
            throw error;
        }
    }

    async connectSSE(port: number = 4000, path: string = '/'): Promise<void> {
        const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN?.trim();
        const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID?.trim();
        const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET?.trim();
        const authCodes: Record<string, AuthCode> = {};

        this.app.use(express.urlencoded({ extended: false }));

        // OAuth discovery endpoints
        this.app.get('/.well-known/oauth-protected-resource', (req: Request, res: Response) => {
            const base = `https://${req.headers.host}`;
            res.json({ resource: `${base}/mcp`, authorization_servers: [base] });
        });

        this.app.get('/.well-known/oauth-authorization-server', (req: Request, res: Response) => {
            const base = `https://${req.headers.host}`;
            res.json({
                issuer: base,
                authorization_endpoint: `${base}/authorize`,
                token_endpoint: `${base}/oauth/token`,
                grant_types_supported: ['authorization_code', 'client_credentials'],
                code_challenge_methods_supported: ['S256'],
                response_types_supported: ['code']
            });
        });

        this.app.get('/authorize', (req: Request, res: Response) => {
            const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state } = req.query as Record<string, string>;
            if (client_id !== OAUTH_CLIENT_ID) { res.status(401).json({ error: 'invalid_client' }); return; }
            if (response_type !== 'code') { res.status(400).json({ error: 'unsupported_response_type' }); return; }
            if (!code_challenge) { res.status(400).json({ error: 'code_challenge required' }); return; }
            const code = randomUUID();
            authCodes[code] = { codeChallenge: code_challenge, codeChallengeMethod: code_challenge_method || 'S256', redirectUri: redirect_uri, expiresAt: Date.now() + 5 * 60 * 1000 };
            const redirectUrl = new URL(redirect_uri);
            redirectUrl.searchParams.set('code', code);
            if (state) redirectUrl.searchParams.set('state', state);
            res.redirect(redirectUrl.toString());
        });

        this.app.post('/oauth/token', (req: Request, res: Response) => {
            if (!OAUTH_CLIENT_ID || !AUTH_TOKEN) { res.status(500).json({ error: 'server_misconfigured' }); return; }
            const grant_type = req.body.grant_type;
            if (grant_type === 'authorization_code') {
                const { code, code_verifier, redirect_uri } = req.body;
                const stored = authCodes[code];
                if (!stored || stored.expiresAt < Date.now()) { res.status(400).json({ error: 'invalid_grant' }); return; }
                const expected = createHash('sha256').update(code_verifier).digest('base64url');
                if (expected !== stored.codeChallenge) { res.status(400).json({ error: 'invalid_grant' }); return; }
                if (redirect_uri && redirect_uri !== stored.redirectUri) { res.status(400).json({ error: 'invalid_grant' }); return; }
                delete authCodes[code];
                res.json({ access_token: AUTH_TOKEN, token_type: 'Bearer', expires_in: 2592000 });
                return;
            }
            if (!OAUTH_CLIENT_SECRET) { res.status(500).json({ error: 'server_misconfigured' }); return; }
            let client_id: string | undefined, client_secret: string | undefined;
            const basicAuth = req.headers['authorization'];
            if (basicAuth?.startsWith('Basic ')) {
                const decoded = Buffer.from(basicAuth.slice(6), 'base64').toString();
                const colon = decoded.indexOf(':');
                client_id = decoded.slice(0, colon); client_secret = decoded.slice(colon + 1);
            } else { client_id = req.body.client_id; client_secret = req.body.client_secret; }
            if (client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET) { res.status(401).json({ error: 'invalid_client' }); return; }
            res.json({ access_token: AUTH_TOKEN, token_type: 'Bearer', expires_in: 2592000 });
        });

        this.app.get('/health', (_req: Request, res: Response) => {
            res.json({ status: 'ok', connections: this.connections.size });
        });

        // Bearer token guard — protects all MCP routes
        this.app.use((req: Request, res: Response, next: NextFunction) => {
            if (['/health', '/authorize', '/oauth/token'].includes(req.path) || req.path.startsWith('/.well-known/')) return next();
            if (!AUTH_TOKEN) return next();
            const authHeader = req.headers['authorization'];
            if (!authHeader?.startsWith('Bearer ')) {
                res.status(401).set('WWW-Authenticate', `Bearer resource_metadata="https://${req.headers.host}/.well-known/oauth-protected-resource"`).json({ error: 'Unauthorized' });
                return;
            }
            if (authHeader.slice(7) !== AUTH_TOKEN) {
                res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'Unauthorized' });
                return;
            }
            next();
        });

        this.app.get(path, (_, res: Response) => {
            const transport = new SSEServerTransport(path, res);
            this.trackConnection(transport);
            
            this.server.connect(transport).catch(error => {
                this.untrackConnection(transport);
                console.error('Failed to connect transport:', error);
                res.status(500).end();
            });

            // Handle client disconnect
            res.on('close', () => {
                this.untrackConnection(transport);
            });
        });

        await new Promise<void>((resolve) => {
            this.app.listen(port, () => {
                console.info(`Server listening on port ${port}`);
                resolve();
            });
        });
    }
}


