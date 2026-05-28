// Secure storage backed by iOS Keychain / Android Keystore (via
// expo-secure-store). Holds the user's FROST share and account
// metadata. Never written to disk in plaintext.

import * as SecureStore from "expo-secure-store";

const KEY_SHARE = "vouch.share";
const KEY_ACCOUNT_PUBKEY = "vouch.accountPubX";
const KEY_ACCOUNT_ADDR = "vouch.accountAddress";

export async function saveShare(shareBytesHex: string): Promise<void> {
  await SecureStore.setItemAsync(KEY_SHARE, shareBytesHex, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED,
  });
}

export async function loadShare(): Promise<string | null> {
  return SecureStore.getItemAsync(KEY_SHARE);
}

export async function clearShare(): Promise<void> {
  await SecureStore.deleteItemAsync(KEY_SHARE);
}

export async function saveAccount(pubXHex: string, address: string): Promise<void> {
  await SecureStore.setItemAsync(KEY_ACCOUNT_PUBKEY, pubXHex);
  await SecureStore.setItemAsync(KEY_ACCOUNT_ADDR, address);
}

export async function loadAccount(): Promise<{ pubX: string; address: string } | null> {
  const pubX = await SecureStore.getItemAsync(KEY_ACCOUNT_PUBKEY);
  const address = await SecureStore.getItemAsync(KEY_ACCOUNT_ADDR);
  if (!pubX || !address) return null;
  return { pubX, address };
}
