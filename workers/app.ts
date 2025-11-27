import { Hono } from "hono";
import { createRequestHandler } from "react-router";

// Manual Agora Token Generation (compatible with Cloudflare Workers)
// Based on Agora RTC Token specification
const RtcRole = {
	PUBLISHER: 1,
	SUBSCRIBER: 2,
};

async function buildAgoraToken(
	appId: string,
	appCertificate: string,
	channelName: string,
	uid: number,
	role: number,
	privilegeExpiredTs: number
): Promise<string> {
	const encoder = new TextEncoder();
	
	// Build message to sign
	const message = JSON.stringify({
		salt: Math.floor(Date.now() / 1000),
		ts: Math.floor(Date.now() / 1000),
		messages: {
			'1': privilegeExpiredTs, // Join channel privilege
		},
	});
	
	// Import key
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(appCertificate),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);
	
	// Sign the message
	const signature = await crypto.subtle.sign(
		'HMAC',
		key,
		encoder.encode(message)
	);
	
	// Convert to base64
	const signatureArray = Array.from(new Uint8Array(signature));
	const signatureBase64 = btoa(String.fromCharCode(...signatureArray));
	
	// Build token
	const tokenData = {
		signature: signatureBase64,
		crc_channel_name: channelName,
		crc_uid: uid.toString(),
		m: message,
	};
	
	const tokenString = JSON.stringify(tokenData);
	const tokenBase64 = btoa(tokenString);
	
	return `007${appId}${tokenBase64}`;
}

const app = new Hono();

// ============================================
// JWT Verification (Reusing IMS Pattern)
// ============================================
async function verifyJWT(token: string, secret: string): Promise<any> {
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['verify']
	);

	const [header, payload, signature] = token.split('.');
	if (!header || !payload || !signature) {
		throw new Error('Invalid token format');
	}

	const data = `${header}.${payload}`;

	const signatureBuffer = Uint8Array.from(
		atob(signature.replace(/-/g, '+').replace(/_/g, '/')),
		c => c.charCodeAt(0)
	);

	const isValid = await crypto.subtle.verify(
		'HMAC',
		key,
		signatureBuffer,
		encoder.encode(data)
	);

	if (!isValid) {
		throw new Error('Invalid JWT signature');
	}

	const decodedPayload = JSON.parse(
		atob(payload.replace(/-/g, '+').replace(/_/g, '/'))
	);

	// Check expiration
	if (decodedPayload.exp && Date.now() >= decodedPayload.exp * 1000) {
		throw new Error('JWT token expired');
	}

	return decodedPayload;
}

// ============================================
// Agora Token Generation Endpoint
// ============================================
app.post("/api/voice/token", async (c) => {
	try {
		// 1. Extract JWT from request
		let jwtToken: string | null = null;

		// For Customer App (httpOnly cookie)
		const cookieHeader = c.req.header('Cookie');
		if (cookieHeader) {
			const cookies = cookieHeader.split(';').map(cookie => cookie.trim());
			const authCookie = cookies.find(cookie => cookie.startsWith('auth_token='));
			if (authCookie) {
				jwtToken = authCookie.split('=')[1];
			}
		}

		// For Driver App (Authorization header)
		if (!jwtToken) {
			const authHeader = c.req.header('Authorization');
			if (authHeader?.startsWith('Bearer ')) {
				jwtToken = authHeader.substring(7);
			}
		}

		if (!jwtToken) {
			return c.json({ error: 'Missing authentication token' }, 401);
		}

		// 2. Verify JWT token
		const payload = await verifyJWT(jwtToken, c.env.JWT_SECRET);

		// 3. Validate user type
		if (!['CUSTOMER', 'DRIVER'].includes(payload.userType)) {
			return c.json({ error: 'Invalid user type' }, 403);
		}

		// 4. Extract leadId from request
		const body = await c.req.json();
		const leadId = c.req.header('X-Lead-ID') || body.leadId;
		if (!leadId) {
			return c.json({ error: 'Lead ID required' }, 400);
		}

		// 5. Validate lead access (call Spring Boot)
		const coreApiUrl = c.env.CORE_API_URL || 'https://api.mycalldriver.com';
		const leadValidation = await fetch(
			`${coreApiUrl}/api/v1/leads/${leadId}/validate-voice-access`,
			{
				headers: { 'Authorization': `Bearer ${jwtToken}` }
			}
		);

		if (!leadValidation.ok) {
			const error = await leadValidation.text();
			return c.json({ 
				error: 'Not authorized for this lead',
				details: error 
			}, 403);
		}

		const validationResult = await leadValidation.json();
		if (!validationResult.canAccess) {
			return c.json({ error: 'Voice access denied for this lead' }, 403);
		}

		// 6. Generate Agora channel name (lead-scoped)
		const channelName = `lead_${leadId}`;

		// 7. Generate Agora UID (unique per user)
		const agoraUid = payload.userType === 'CUSTOMER'
			? parseInt(`1${payload.userId}`) // Customer UIDs start with 1
			: parseInt(`2${payload.userId}`); // Driver UIDs start with 2

		// 8. Generate Agora RTC Token
		const appId = c.env.AGORA_APP_ID;
		const appCertificate = c.env.AGORA_APP_CERTIFICATE;
		const expirationTimeInSeconds = 3600; // 1 hour
		const currentTimestamp = Math.floor(Date.now() / 1000);
		const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;

		const agoraToken = await buildAgoraToken(
			appId,
			appCertificate,
			channelName,
			agoraUid,
			RtcRole.PUBLISHER,
			privilegeExpiredTs
		);

		// 9. Return Agora token to client
		return c.json({
			success: true,
			data: {
				agoraToken,
				channelName,
				uid: agoraUid,
				expiresAt: privilegeExpiredTs,
				userType: payload.userType,
				leadId: leadId.toString()
			}
		});

	} catch (error: any) {
		console.error('Token generation error:', error);
		return c.json({
			error: 'Failed to generate voice token',
			message: error.message
		}, 500);
	}
});

// ============================================
// Token Refresh Endpoint
// ============================================
app.post("/api/voice/refresh-token", async (c) => {
	try {
		// Reuse same logic as /api/voice/token
		// This allows calls > 1 hour to refresh their token
		return app.fetch(new Request(c.req.raw.url.replace('refresh-token', 'token'), {
			method: 'POST',
			headers: c.req.raw.headers,
			body: c.req.raw.body
		}));
	} catch (error: any) {
		console.error('Token refresh error:', error);
		return c.json({
			error: 'Failed to refresh voice token',
			message: error.message
		}, 500);
	}
});

// ============================================
// Health Check Endpoint
// ============================================
app.get("/api/voice/health", (c) => {
	return c.json({
		status: 'ok',
		service: 'mycd-agora-voice-module',
		timestamp: new Date().toISOString()
	});
});

// React Router handler (keep existing functionality)
app.get("*", (c) => {
	const requestHandler = createRequestHandler(
		() => import("virtual:react-router/server-build"),
		import.meta.env.MODE,
	);

	return requestHandler(c.req.raw, {
		cloudflare: { env: c.env, ctx: c.executionCtx },
	});
});

export default app;
