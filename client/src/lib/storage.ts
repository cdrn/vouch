// Secure storage backed by iOS Keychain / Android Keystore (via
// expo-secure-store). v0 demo holds account metadata + the user's MRZ
// (needed for re-scanning during recovery on the same device). v1 will
// also store the device's FROST share once UniFFI ships.

import * as SecureStore from "expo-secure-store";

const KEY_ACCOUNT_ADDRESS = "vouch.accountAddress";
const KEY_ACCOUNT_PUBX = "vouch.accountPubX";
const KEY_SIGNER_URL = "vouch.signerUrl";

export async function saveAccount(opts: {
  address: string;
  pubX: string;
}): Promise<void> {
  await SecureStore.setItemAsync(KEY_ACCOUNT_ADDRESS, opts.address);
  await SecureStore.setItemAsync(KEY_ACCOUNT_PUBX, opts.pubX);
}

export async function loadAccount(): Promise<{
  address: string;
  pubX: string;
} | null> {
  const address = await SecureStore.getItemAsync(KEY_ACCOUNT_ADDRESS);
  const pubX = await SecureStore.getItemAsync(KEY_ACCOUNT_PUBX);
  if (!address || !pubX) return null;
  return { address, pubX };
}

export async function clearAccount(): Promise<void> {
  await SecureStore.deleteItemAsync(KEY_ACCOUNT_ADDRESS);
  await SecureStore.deleteItemAsync(KEY_ACCOUNT_PUBX);
}

export async function saveSignerUrl(url: string): Promise<void> {
  await SecureStore.setItemAsync(KEY_SIGNER_URL, url);
}

export async function loadSignerUrl(): Promise<string | null> {
  return SecureStore.getItemAsync(KEY_SIGNER_URL);
}
