import React, { useState, useEffect } from 'react';

interface ReceiveCredentialResponse {
  message?: string;
  result?: unknown;
  error?: string;
}

async function receiveCredential(
  credentialOfferUri: string,
  holderDid: string,
  password: string
): Promise<ReceiveCredentialResponse> {
  const response = await fetch('/holder/receive-oid4vc', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential_offer_uri: credentialOfferUri,
      holder_did: holderDid,
      password,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ }));
    throw new Error(errorData.error || 'Error al recibir la credencial');
  }

  return response.json();
}

const ReceiveCredentialForm: React.FC = () => {
  const [credentialOfferUri, setCredentialOfferUri] = useState('');
  const [holderDid, setHolderDid] = useState('');
  const [password, setPassword] = useState('');
  const [result, setResult] = useState<ReceiveCredentialResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const storedDid = localStorage.getItem('holderDid');
    const storedPassword = localStorage.getItem('password');
    if (storedDid) setHolderDid(storedDid);
    if (storedPassword) setPassword(storedPassword);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);

    try {
      setLoading(true);
      const res = await receiveCredential(credentialOfferUri, holderDid, password);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Error inesperado');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <label>
          credential_offer_uri:
          <input
            type="text"
            value={credentialOfferUri}
            onChange={(e) => setCredentialOfferUri(e.target.value)}
          />
        </label>
        <button type="submit" disabled={loading}>
          Recibir
        </button>
      </form>

      {loading && <p>Procesando...</p>}
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
};

export default ReceiveCredentialForm;

