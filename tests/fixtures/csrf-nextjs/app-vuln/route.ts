export async function POST(request: Request) {
  const body = await request.json();
  await db.transfer(body.amount, body.to);
  return Response.json({ ok: true });
}
