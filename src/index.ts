// Title: PrevLife Account Validation Worker
// Purpose:
// - Store account validation token hashes in Cloudflare D1
// - Validate account email tokens for doctors, patients, and staff
// - Keep D1 access outside the Next.js frontend app

export interface Env {
	DB: D1Database;
	API_TOKEN: string;
  }
  
  // SECTION 1: JSON Response Helper
  function json(data: unknown, status = 200) {
	return new Response(JSON.stringify(data), {
	  status,
	  headers: {
		"content-type": "application/json",
	  },
	});
  }
  
  // SECTION 2: SHA-256 Token Hash Helper
  async function sha256Hex(value: string) {
	const encoded = new TextEncoder().encode(value);
	const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
  
	return [...new Uint8Array(hashBuffer)]
	  .map((byte) => byte.toString(16).padStart(2, "0"))
	  .join("");
  }
  
  // SECTION 3: API Token Authorization Helper
  function isAuthorized(req: Request, env: Env) {
	const token = req.headers.get("x-api-token");
	return Boolean(token && token === env.API_TOKEN);
  }
  
  // SECTION 4: Worker Fetch Handler
  export default {
	async fetch(req: Request, env: Env) {
	  const url = new URL(req.url);
  
	  // SECTION 4A: Require API Token
	  if (!isAuthorized(req, env)) {
		return json({ ok: false, error: "unauthorized" }, 401);
	  }
  
	  // SECTION 4B: Create Account Validation Token
	  if (req.method === "POST" && url.pathname === "/account-validation/create") {
		
		const body: any = await req.json();
		const id = crypto.randomUUID();
		const tokenHash = await sha256Hex(String(body.token || ""));
  
		const now = new Date();
		const expiresAt = new Date(now.getTime() + 1000 * 60 * 60 * 24);
  
		await env.DB.prepare(`
		  INSERT INTO account_validation_tokens (
			id,
			account_type,
			first_name,
			last_name,
			email,
			mobile,
			token_hash,
			status,
			created_at,
			expires_at,
			validated_at
		  )
		  VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, NULL)
		`)
		  .bind(
			id,
			String(body.account_type || ""),
			body.first_name || null,
			body.last_name || null,
			String(body.email || "").toLowerCase(),
			body.mobile || null,
			tokenHash,
			now.toISOString(),
			expiresAt.toISOString()
		  )
		  .run();
  
		return json({
		  ok: true,
		  id,
		  expires_at: expiresAt.toISOString(),
		});
	  }
  
	  // SECTION 4C: Validate Account Email Token
	  if (req.method === "POST" && url.pathname === "/account-validation/validate") {
		const body: any = await req.json();
  
		const email = String(body.email || "").toLowerCase();
		const tokenHash = await sha256Hex(String(body.token || ""));
		const nowIso = new Date().toISOString();
  
		const row = await env.DB.prepare(`
		  SELECT id, status, expires_at
		  FROM account_validation_tokens
		  WHERE email = ?
			AND token_hash = ?
		  LIMIT 1
		`)
		  .bind(email, tokenHash)
		  .first();
  
		if (!row) {
		  return json({ ok: false, error: "invalid_token" }, 404);
		}
  
		if (row.status === "validated") {
		  return json({ ok: true, status: "already_validated" });
		}
  
		if (String(row.expires_at) < nowIso) {
		  return json({ ok: false, error: "token_expired" }, 410);
		}
  
		await env.DB.prepare(`
		  UPDATE account_validation_tokens
		  SET status = 'validated',
			  validated_at = ?
		  WHERE id = ?
		`)
		  .bind(nowIso, row.id)
		  .run();
  
		return json({ ok: true, status: "validated" });
	  }
  
	  // SECTION 4D: Not Found
	  return json({ ok: false, error: "not_found" }, 404);
	},
  } satisfies ExportedHandler<Env>;