export async function POST(request: Request) {
  // Verify the CSRF token before proceeding.
  const csrfToken = request.headers.get("x-csrf-token");
  if (csrfToken !== expectedToken) {
    return new Response("Forbidden", { status: 403 });
  }
  const body = await request.json();
  await db.transfer(body.amount, body.to);
  return Response.json({ ok: true });
}
