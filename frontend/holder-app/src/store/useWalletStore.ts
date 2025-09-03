import { create } from 'zustand';

interface WalletState {
  holderDid: string;
  password: string;
  setHolderDid: (did: string) => void;
  setPassword: (pw: string) => void;
}

export const useWalletStore = create<WalletState>((set) => ({
  holderDid: localStorage.getItem('holderDid') || '',
  // Start with an empty password so the user must provide one
  password: '',
  setHolderDid: (did) => {
    localStorage.setItem('holderDid', did);
    set({ holderDid: did });
  },
  setPassword: (pw) => set({ password: pw }),
}));

