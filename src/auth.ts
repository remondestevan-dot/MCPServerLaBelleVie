import { timingSafeEqual } from 'node:crypto';
import DescopeClient from '@descope/node-sdk';
import type { AuthInfo } from '@modelcontextprotocol/server';

/**
 * Dual authentication for the MCP endpoint.
 *
 * 1. Static bearer (LBV_API_TOKEN) — used by the lbv CLI.
 * 2. Descope OAuth access token — used by Claude Desktop / claude.ai.
 *
 * Only the server-side allow-listed user is accepted.
 */

const GROCERIES_SCOPE = 'groceries';
const DEFAULT_DESCOPE_BASE_URL = 'https://api.descope.com';

/**
 * Issuer URL for RFC 9728 protected-resource metadata.
 * Uses the MCP Server-specific Descope issuer.
 */
export function descopeIssuerUrl(): string | undefined {
  return process.env.DESCOPE_MCP_SERVER_ISSUER;
}

/** True when OAuth is configured. */
export function hasOAuthConfig(): boolean {
  return Boolean(
    process.env.DESCOPE_PROJECT_ID &&
      process.env.DESCOPE_MCP_SERVER_ISSUER &&
      (process.env.LBV_ALLOWED_EMAIL || process.env.LBV_ALLOWED_SUBJECT),
  );
}

/** Constant-time bearer-token comparison. */
function tokenMatches(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function verifyStaticToken(bearerToken: string): AuthInfo | undefined {
  const expected = process.env.LBV_API_TOKEN;
  if (!expected) return undefined;
  if (!tokenMatches(bearerToken, expected)) return undefined;

  return {
    token: bearerToken,
    scopes: [GROCERIES_SCOPE],
    clientId: 'lbv-agent',
  };
}

type Descope = ReturnType<typeof DescopeClient>;

// Module-level singleton.
let descopeClient: Descope | undefined;
let descopeClientProjectId: string | undefined;

function getDescopeClient(): Descope | undefined {
  const projectId = process.env.DESCOPE_PROJECT_ID;

  if (!projectId) return undefined;

  if (!descopeClient || descopeClientProjectId !== projectId) {
    descopeClient = DescopeClient({
      projectId,
      baseUrl:
        process.env.DESCOPE_BASE_URL || DEFAULT_DESCOPE_BASE_URL,
    });

    descopeClientProjectId = projectId;
  }

  return descopeClient;
}

export function resetDescopeClientForTests(): void {
  descopeClient = undefined;
  descopeClientProjectId = undefined;
}

/**
 * Extract email from the Descope token.
 */
function extractEmail(
  token: Record<string, unknown>,
): string | undefined {
  const email = token.email;

  if (typeof email !== 'string' || email.length === 0) {
    return undefined;
  }

  return email.toLowerCase();
}

async function verifyDescopeToken(
  bearerToken: string,
): Promise<AuthInfo | undefined> {
  const client = getDescopeClient();

  const allowedEmail = process.env.LBV_ALLOWED_EMAIL?.toLowerCase();
  const allowedSubject = process.env.LBV_ALLOWED_SUBJECT;

  if (!client || (!allowedEmail && !allowedSubject)) {
    return undefined;
  }

  try {
    const authInfo = await client.validateSession(bearerToken);
    const token = authInfo.token as Record<string, unknown>;

    const email = extractEmail(token);

    const emailAllowed = Boolean(
      allowedEmail && email === allowedEmail,
    );

    const subjectAllowed = Boolean(
      allowedSubject && token.sub === allowedSubject,
    );

    if (!emailAllowed && !subjectAllowed) {
      return undefined;
    }

    return {
      token: bearerToken,
      scopes: [GROCERIES_SCOPE],
      clientId:
        typeof token.azp === 'string'
          ? token.azp
          : 'descope-client',
      expiresAt:
        typeof token.exp === 'number'
          ? token.exp
          : undefined,
      extra: {
        sub: token.sub,
        email,
      },
    };
  } catch (error) {
    console.error('Descope token validation failed:', error);
    return undefined;
  }
}

/**
 * Verify a bearer token via either authentication path.
 */
export async function verifyToken(
  _req: Request,
  bearerToken?: string,
): Promise<AuthInfo | undefined> {
  if (!bearerToken) return undefined;

  return (
    verifyStaticToken(bearerToken) ??
    (await verifyDescopeToken(bearerToken))
  );
}
