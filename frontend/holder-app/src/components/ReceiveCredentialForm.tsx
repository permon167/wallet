import { useState } from 'react';
import { receiveCredential } from '../services/api';
import { useWalletStore } from '../store/useWalletStore';

export default function ReceiveCredentialForm() {
  const [offerUri, setOfferUri] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const holderDid = useWalletStore((s) => s.holderDid);
  const password = useWalletStore((s) => s.password);

  const handleReceive = async () => {
    try {
      const res = await receiveCredential({
        credential_offer_uri: offerUri,
        holder_did: holderDid,
        password,
      });
      setResult(res);
      setOfferUri('');
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <div>
      <h2>Recibir credencial</h2>
      <input
        value={offerUri}
        onChange={(e) => setOfferUri(e.target.value)}
        placeholder="credential_offer_uri"
      />
      <button onClick={handleReceive} disabled={!offerUri}>Recibir</button>
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
      {error && <p>{error}</p>}
    </div>
  );
}

