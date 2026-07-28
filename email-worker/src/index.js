/**
 * Standalone Cloudflare Email Worker.
 * Triggered by Cloudflare Email Routing when mail arrives for trueseal.help.
 * Extracts the DKIM selector (s=) and signing domain (d=) from the
 * DKIM-Signature header and logs them. No other side effects yet.
 */

// Splits the raw email into an array of unfolded "Name: value" header lines.
// Email headers can wrap onto multiple physical lines (a continuation line
// starts with a space or tab) — this stitches those back into one line per
// header so a simple regex/split can read the full value.
function getUnfoldedHeaderLines(rawEmailText) {
  const headerEnd = rawEmailText.search(/\r?\n\r?\n/);
  const headerBlock = headerEnd === -1 ? rawEmailText : rawEmailText.slice(0, headerEnd);
  const lines = headerBlock.split(/\r?\n/);

  const unfolded = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ' ' + line.trim();
    } else if (line.trim() !== '') {
      unfolded.push(line);
    }
  }
  return unfolded;
}

// Returns the value of every header matching `name` (case-insensitive).
// Returns an array because a message can legally carry more than one
// DKIM-Signature header (e.g. mailing lists or forwarders add their own).
function getHeaderValues(unfoldedLines, name) {
  const values = [];
  for (const line of unfoldedLines) {
    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) continue;

    const headerName = line.slice(0, colonIndex).trim();
    if (headerName.toLowerCase() === name.toLowerCase()) {
      values.push(line.slice(colonIndex + 1).trim());
    }
  }
  return values;
}

// The frontend generates addresses like "a1b2c3@trueseal.help" — the whole
// local part (everything before "@") IS the token, no "+" tag. This relies
// on a Catch-all Email Routing rule sending every address at the domain to
// this Worker, since tokens no longer share a common prefix to route on.
// Returns null only if the address is malformed (no "@" at all).
function extractToken(toAddress) {
  const atIndex = toAddress.indexOf('@');
  if (atIndex === -1) return null;

  return toAddress.slice(0, atIndex);
}

// A DKIM-Signature value is a semicolon-separated list of tag=value pairs,
// e.g. "v=1; a=rsa-sha256; d=example.com; s=selector1; ...".
// This turns that into a plain object: { v: "1", a: "rsa-sha256", ... }.
function parseDkimTags(headerValue) {
  const tags = {};
  for (const part of headerValue.split(';')) {
    const eqIndex = part.indexOf('=');
    if (eqIndex === -1) continue;

    const key = part.slice(0, eqIndex).trim();
    const value = part.slice(eqIndex + 1).trim();
    tags[key] = value;
  }
  return tags;
}

// How long a saved result stays in KV before it's auto-deleted. The frontend
// only polls for 2 minutes, so anything much longer than that is just
// tidiness — it keeps the namespace from accumulating tokens no one is
// ever going to look up again.
const KV_RESULT_TTL_SECONDS = 30 * 60;

// Serves the page's polling requests: GET /lookup?token=... -> tells the
// frontend whether a result has been saved yet for that token.
async function handleLookup(request, env) {
  const corsHeaders = { 'Access-Control-Allow-Origin': '*' };
  const jsonHeaders = { 'Content-Type': 'application/json', ...corsHeaders };

  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return new Response(JSON.stringify({ error: 'Missing "token" query parameter.' }), {
      status: 400,
      headers: jsonHeaders,
    });
  }

  const stored = await env.DKIM_RESULTS.get(token);
  if (!stored) {
    return new Response(JSON.stringify({ found: false }), { headers: jsonHeaders });
  }

  const { selector, domain } = JSON.parse(stored);
  return new Response(JSON.stringify({ found: true, selector, domain }), { headers: jsonHeaders });
}

export default {
  async email(message, env, ctx) {
    // `message.raw` is a ReadableStream of the full raw email (headers + body).
    // Wrapping it in a Response and calling .text() is the simplest way to
    // read a stream to completion in a Worker.
    const rawEmailText = await new Response(message.raw).text();

    const token = extractToken(message.to);
    const tokenLabel = token ?? '(none — recipient address had no local part before "@")';

    const headerLines = getUnfoldedHeaderLines(rawEmailText);
    const dkimSignatures = getHeaderValues(headerLines, 'DKIM-Signature');

    if (dkimSignatures.length === 0) {
      console.log(`token: ${tokenLabel} — No DKIM-Signature header found on message from ${message.from} to ${message.to}.`);
      return;
    }

    const parsedSignatures = dkimSignatures.map(parseDkimTags);

    parsedSignatures.forEach((tags, index) => {
      const selector = tags.s ?? '(missing s= tag)';
      const domain = tags.d ?? '(missing d= tag)';

      console.log(
        `token: ${tokenLabel}, selector: ${selector}, domain: ${domain}` +
        (parsedSignatures.length > 1 ? ` [signature ${index + 1}/${parsedSignatures.length}]` : '')
      );
    });

    // Save the result to KV (Cloudflare's key-value store) so the frontend's
    // polling requests can find it by token. We only save if there's a usable
    // selector, and we use the first DKIM-Signature — that's normally the
    // sending domain's own signature, which is what the user actually wants.
    const primary = parsedSignatures[0];
    if (token && primary.s) {
      await env.DKIM_RESULTS.put(
        token,
        JSON.stringify({ selector: primary.s, domain: primary.d ?? null }),
        { expirationTtl: KV_RESULT_TTL_SECONDS }
      );
      console.log(`Saved result for token "${token}" to KV.`);
    }

    // Not forwarding or rejecting the message — this Worker only observes it
    // for now. Uncomment the line below once you want mail to keep landing
    // in your real inbox too:
    // await message.forward('your-real-address@gmail.com');
  },

  // Serves the frontend's polling requests over plain HTTP, at this Worker's
  // own workers.dev address (separate from the trueseal.help site).
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/lookup') {
      return handleLookup(request, env);
    }
    return new Response('Not found', { status: 404 });
  },
};
