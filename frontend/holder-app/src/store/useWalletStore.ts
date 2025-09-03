import { create } from 'zustand';

interface WalletState {
  holderDid: string;
  password: string;
  setHolderDid: (did: string) => void;
  setPassword: (pw: string) => void;
}

export const useWalletStore = create<WalletState>((set) => ({
  holderDid:
    localStorage.getItem('holderDid') || localStorage.getItem('holder_did') || '',
  password: localStorage.getItem('wallet_password') || '',
  setHolderDid: (did) => {
    localStorage.setItem('holderDid', did);
    set({ holderDid: did });
  },
  setPassword: (pw) => {
    localStorage.setItem('wallet_password', pw);
    set({ password: pw });
  },
}));

