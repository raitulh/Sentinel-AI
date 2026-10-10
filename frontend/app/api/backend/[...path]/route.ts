import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

const COOKIE_NAME = "sentinel_access";
const COOKIE_MAX_AGE = 60 * 30;
const API_BASE = (process.env.BACKEND_INTERNAL_URL || "http://localhost:8000").replace(/\/$/, "");

type Context = { params: Promise<{ path: string[] }> };

async function proxy(request: NextRequest, context: Context) {
  const { path: segments } = await context.params;
  const path = segments.join("/");
  const method = request.method.toUpperCase();
  const jar = await cookies();

  if (path === "logout") {
    const response = NextResponse.json({ ok: true });
    response.cookies.set(COOKIE_NAME, "", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 0 });
    return response;
  }

  if (["POST", "PATCH", "DELETE"].includes(method)) {
    const origin = request.headers.get("origin");
    const isDev = process.env.NODE_ENV !== "production";
    if (!isDev && origin) {
      const expectedOrigin = process.env.APP_ORIGIN || request.nextUrl.origin;
      try {
        const originUrl = new URL(origin);
        const isLocal = originUrl.hostname === "localhost" || originUrl.hostname === "127.0.0.1";
        if (!isLocal && originUrl.origin !== new URL(expectedOrigin).origin) {
          return NextResponse.json({ detail: "Missing or invalid request origin" }, { status: 403 });
        }
      } catch {
        return NextResponse.json({ detail: "Missing or invalid request origin" }, { status: 403 });
      }
    }
  }

  const token = jar.get(COOKIE_NAME)?.value;
  const headers = new Headers();
  headers.set("accept", request.headers.get("accept") || "application/json");
  if (request.headers.get("content-type")) headers.set("content-type", request.headers.get("content-type")!);
  if (token) headers.set("authorization", `Bearer ${token}`);
  const body = ["GET", "HEAD"].includes(method) ? undefined : await request.arrayBuffer();
  let upstream: Response;
  try {
    upstream = await fetch(`${API_BASE}/api/v1/${path}${request.nextUrl.search}`, {
      method, headers, body, cache: "no-store", redirect: "manual", signal: AbortSignal.timeout(35_000),
    });
  } catch {
    return NextResponse.json({ detail: "Backend temporarily unavailable" }, { status: 503 });
  }

  const isAuth = path === "auth/login" || path === "auth/register";
  const contentType = upstream.headers.get("content-type") || "application/json";
  if (isAuth && upstream.ok) {
    const payload = await upstream.json() as { access_token?: string; expires_in?: number; user?: unknown };
    if (!payload.access_token) return NextResponse.json({ detail: "Authentication response was incomplete" }, { status: 502 });
    const response = NextResponse.json({ user: payload.user, expires_in: payload.expires_in }, { status: upstream.status });
    response.cookies.set(COOKIE_NAME, payload.access_token, {
      httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/",
      maxAge: Math.max(60, Math.min(payload.expires_in || COOKIE_MAX_AGE, 60 * 60 * 24)),
    });
    return response;
  }

  const responseBody = await upstream.arrayBuffer();
  const responseHeaders = new Headers();
  responseHeaders.set("content-type", contentType);
  responseHeaders.set("cache-control", "no-store");
  const requestId = upstream.headers.get("x-request-id");
  if (requestId) responseHeaders.set("x-request-id", requestId);
  return new Response(responseBody, { status: upstream.status, headers: responseHeaders });
}

export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
