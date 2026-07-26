import { makeFinding, matchAll } from "../core/helpers.js";
import type { Finding, Rule } from "../core/types.js";

const MONGO_METHODS =
  /\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|update|updateOne|updateMany|deleteOne|deleteMany|count|aggregate)\s*\(/;

// db.collection.find(req.body) / User.findOne(req.query) / Model.find(req.params) /
// Model.findOne({ ...req.query }) — spread only ever makes sense inside an object literal, so
// allow an optional leading `{` before the `...req.*` form.
const RAW_REQUEST_OBJECT = new RegExp(
  String.raw`${MONGO_METHODS.source}\s*(req\.(?:body|query|params)|\{?\s*\.\.\.\s*req\.(?:body|query|params))`,
  "g",
);

// { $where: `...${...}...` } or $where: "..." + var — arbitrary JS execution in MongoDB.
const WHERE_INJECTION = /\$where\s*:\s*(`[^`]*\$\{[^}]+\}[^`]*`|(['"]).*?\+\s*[A-Za-z_$])/gs;

const rule: Rule = {
  id: "nosql-injection",
  category: "NoSQL Injection",
  description:
    "Flags MongoDB-style queries built directly from unsanitized request objects (operator injection) or $where clauses built from dynamic strings (JS injection).",
  extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  check(file): Finding[] {
    const findings: Finding[] = [];

    for (const match of matchAll(file.content, RAW_REQUEST_OBJECT)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "MongoDB query built directly from a raw request object — allows operator injection (e.g. { $ne: null }).",
          match.index,
          "Explicitly pick and validate/cast individual fields (e.g. `{ username: String(req.body.username) }`) instead of passing the request object straight into the query.",
        ),
      );
    }

    for (const match of matchAll(file.content, WHERE_INJECTION)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "critical",
          "$where clause built from a dynamic/interpolated string — allows arbitrary JavaScript execution on the database.",
          match.index,
          "Avoid $where entirely; express the condition with standard query operators instead of executing JS server-side.",
        ),
      );
    }

    return findings;
  },
};

export default rule;
