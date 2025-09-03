import CreateDidPage from './pages/CreateDidPage';
import ReceiveCredentialForm from './components/ReceiveCredentialForm';
import CredentialsList from './pages/CredentialsList';
import { useWalletStore } from './store/useWalletStore';

export default function App() {
  const holderDid = useWalletStore((s) => s.holderDid);
  return (
    <div>
      <h1>Holder Wallet</h1>
      {!holderDid ? (
        <CreateDidPage />
      ) : (
        <>
          <ReceiveCredentialForm />
          <CredentialsList />
        </>
      )}
    </div>
  );
}

