import { NextResponse } from "next/server";

const ALLOWED_ORIGINS = ["https://example.com"];

export async function GET(request: Request) {
  const origin = request.headers.get("origin") ?? "";
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return NextResponse.json(
    { ok: true },
    {
      headers: {
        "Access-Control-Allow-Origin": allowedOrigin,
      },
    },
  );
}
