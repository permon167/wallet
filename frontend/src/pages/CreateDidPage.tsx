import React, { useState } from 'react';

async function createDid() {
  const response = await fetch('/holder/create-did-jwk', {
    method: 'POST'
  });
  if (!response.ok) {
    throw new Error('Error creating DID');
  }
  const data = await response.json();
  return data.did;
}

const CreateDidPage: React.FC = () => {
  const [password, setPassword] = useState('');
  const [did, setDid] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCreate = async () => {
    try {
      const pwd = password || 'default';
      const newDid = await createDid();
      setDid(newDid);
      localStorage.setItem('holder_did', newDid);
      localStorage.setItem('wallet_password', pwd);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Unknown error');
    }
  };

  return (
    <div>
      <h1>Crear DID</h1>
      <input
        type="password"
        placeholder="Contraseña de la wallet"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button onClick={handleCreate}>Crear DID</button>
      {did && <p>DID creado: {did}</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
};

export default CreateDidPage;

