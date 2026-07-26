import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const data = { ok: true };
  return NextResponse.json(data, {
    headers: {
      "Access-Control-Allow-Origin": "*",
    },
  });
}

export async function POST(request: Request) {
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "Access-Control-Allow-Origin": request.headers.get("origin"),
    },
  });
}
