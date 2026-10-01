/**
 * Errors and JSON helpers of the auth module, so it does not depend on the project's
 * own HTTP code. The project's error handler turns an AuthError into a JSON response:
 *   { error: err.message, details: err.details } with status err.status
 */
export class AuthError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export async function readJson(request) {
  try {
    return await request.json();
  } catch {
    throw new AuthError(400, 'Request body must be valid JSON');
  }
}
