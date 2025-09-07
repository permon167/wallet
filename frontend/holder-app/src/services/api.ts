import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_FASTAPI_URL || 'http://localhost:8000',
});

export async function createDid() {
  const { data } = await api.post('/holder/create-did-jwk');
  return data;
}

export async function receiveCredential(payload: {credential_offer_uri: string; holder_did: string; password: string;}) {
  try {
    const { data } = await api.post('/holder/receive-oid4vc', payload);
    return data;
  } catch (e: any) {
    throw new Error(e.response?.data?.error || e.message);
  }
}

export async function listCredentials(payload: {holder_did: string; password: string;}) {
  try {
    const { data } = await api.post('/holder/credentials', payload);
    return data;
  } catch (e: any) {
    throw new Error(e.response?.data?.error || e.message);
  }
}

export async function deleteCredential(payload: {holder_did: string; password: string; index: number;}) {
  try {
    const { data } = await api.post('/holder/delete-credential', payload);
    return data;
  } catch (e: any) {
    throw new Error(e.response?.data?.error || e.message);
  }
}

export async function presentCredential(payload: {holder_did: string; password: string; index: number; aud: string; nonce: string;}) {
  try {
    const { data } = await api.post('/holder/present-credential-jwt', payload);
    return data;
  } catch (e: any) {
    throw new Error(e.response?.data?.error || e.message);
  }
}

