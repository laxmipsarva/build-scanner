import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "POST") {
    // Verify CSRF token before mutating state.
    if (req.headers["x-csrf-token"] !== process.env.CSRF_SECRET) {
      return res.status(403).end();
    }
    await db.transfer(req.body.amount, req.body.to);
    return res.status(200).json({ ok: true });
  }
  res.status(405).end();
}
