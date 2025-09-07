const API_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL || '';

async function request(path: string, options: RequestInit = {}) {
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      },
      ...options
    });

    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        const errorData = await response.json();
        message = errorData.message || errorData.error || message;
      } catch (err) {
        const text = await response.text();
        if (text) message = text;
      }
      throw new Error(message);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }
    return null;
  } catch (error: any) {
    throw new Error(error.message || 'Network error');
  }
}

export async function createDid() {
  return request('/holder/create-did-jwk', { method: 'POST' });
}

export async function receiveCredential(data: unknown) {
  return request('/holder/receive-oid4vc', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

export async function listCredentials() {
  return request('/holder/credentials');
}

export async function deleteCredential(id: string) {
  return request('/holder/delete-credential', {
    method: 'POST',
    body: JSON.stringify({ id })
  });
}

export async function presentCredentialJwt(data: unknown) {
  return request('/holder/present-credential-jwt', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

export async function presentCredential(data: unknown) {
  return request('/presentations/wallet/present', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

export default {
  createDid,
  receiveCredential,
  listCredentials,
  deleteCredential,
  presentCredentialJwt,
  presentCredential
};
