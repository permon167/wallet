import { create } from 'zustand';

interface WalletState {
  holderDid: string;
  password: string;
  setHolderDid: (did: string) => void;
  setPassword: (pw: string) => void;
}

export const useWalletStore = create<WalletState>((set) => ({
  holderDid: localStorage.getItem('holderDid') || '',
  password: 'default',
  setHolderDid: (did) => {
    localStorage.setItem('holderDid', did);
    set({ holderDid: did });
  },
  setPassword: (pw) => set({ password: pw }),
}));

