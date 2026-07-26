import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "POST") {
    await db.transfer(req.body.amount, req.body.to);
    return res.status(200).json({ ok: true });
  }
  res.status(405).end();
}
