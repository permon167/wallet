import { useState } from 'react';
import { createDid } from '../services/api';
import { useWalletStore } from '../store/useWalletStore';

export default function CreateDidPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const setHolderDid = useWalletStore((s) => s.setHolderDid);
  const holderDid = useWalletStore((s) => s.holderDid);
  const password = useWalletStore((s) => s.password);
  const setPassword = useWalletStore((s) => s.setPassword);

  const handleCreate = async () => {
    try {
      setLoading(true);
      const pwd = password || 'default';
      setPassword(pwd);
      const res = await createDid();
      setHolderDid(res.did);
      setError('');
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
        placeholder="Contraseña de la wallet"
      />
      <button onClick={handleCreate} disabled={loading}>Crear</button>
      {holderDid && <p>DID creado: {holderDid}</p>}
      {error && <p>{error}</p>}
    </div>
  );
}

