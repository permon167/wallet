import { useState } from 'react';
import { createDid } from '../services/api';
import { useWalletStore } from '../store/useWalletStore';

export default function CreateDidPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const setHolderDid = useWalletStore((s) => s.setHolderDid);
  const password = useWalletStore((s) => s.password);
  const setPassword = useWalletStore((s) => s.setPassword);

  const handleCreate = async () => {
    try {
      setLoading(true);
      const res = await createDid();
      setHolderDid(res.did);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2>Crear DID</h2>
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="password"
      />
      <button onClick={handleCreate} disabled={loading}>Crear</button>
      {error && <p>{error}</p>}
    </div>
  );
}

