import { useEffect, useState } from 'react';
import { listCredentials, deleteCredential, presentCredential } from '../services/api';
import { useWalletStore } from '../store/useWalletStore';

export default function CredentialsList() {
  const holderDid = useWalletStore((s) => s.holderDid);
  const password = useWalletStore((s) => s.password);
  const [creds, setCreds] = useState<any[]>([]);
  const [error, setError] = useState('');
  const [vp, setVp] = useState('');

  const fetchCreds = async () => {
    try {
      const res = await listCredentials({ holder_did: holderDid, password });
      setCreds(res.credentials || []);
    } catch (e: any) {
      setError(e.message);
    }
  };

  useEffect(() => {
    fetchCreds();
  }, []);

  const handleDelete = async (index: number) => {
    await deleteCredential({ holder_did: holderDid, password, index });
    fetchCreds();
  };

  const handlePresent = async (index: number) => {
    try {
      const res = await presentCredential({ holder_did: holderDid, password, index, aud: 'https://verifier.example', nonce: '1234' });
      setVp(res.vp_jwt);
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <div>
      <h2>Credenciales</h2>
      {error && <p>{error}</p>}
      <ul>
        {creds.map((c, i) => (
          <li key={i}>
            <span>Credencial {i}</span>
            <button onClick={() => handlePresent(i)}>Presentar</button>
            <button onClick={() => handleDelete(i)}>Eliminar</button>
          </li>
        ))}
      </ul>
      {vp && (
        <div>
          <h3>VP-JWT</h3>
          <pre>{vp}</pre>
        </div>
      )}
    </div>
  );
}

