import { useState } from "react";
import {
  ActivityIndicator,
  Alert,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import { walletCreate } from "../lib/signer";
import { saveAccount, saveSignerUrl } from "../lib/storage";
import type { RootStackParamList } from "../navigation";

type Props = NativeStackScreenProps<RootStackParamList, "Onboarding">;

const DEFAULT_SIGNER = "http://localhost:8089";

// For onboarding v0 the user types a "secret" string — we hash it into
// a 32-byte H_passport so the signer indexes the account by it. When
// recovery happens, the user re-scans their passport (real BAC) and we
// recompute H_passport from the parsed MRZ.
//
// In v1 (with real native crypto) the device would compute H_passport
// directly from the passport at onboarding time too. v0 lets you create
// without a passport so you can demo the create + execute flow before
// tapping a passport.
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  // expo-crypto exposes digest in a portable way.
  const { digestStringAsync, CryptoDigestAlgorithm } = await import("expo-crypto");
  return digestStringAsync(CryptoDigestAlgorithm.SHA256, input, {
    encoding: "hex" as any,
  });
  // (data unused; kept for the moment in case we switch to digest())
  void data;
}

export function OnboardingScreen({ navigation }: Props) {
  const [signerUrl, setSignerUrl] = useState(DEFAULT_SIGNER);
  const [recoveryPhrase, setRecoveryPhrase] = useState("");
  const [busy, setBusy] = useState(false);

  async function onCreate() {
    if (!recoveryPhrase.trim()) {
      Alert.alert("Pick a recovery phrase", "Anything works for the demo.");
      return;
    }
    setBusy(true);
    try {
      const hPassportHex = await sha256Hex(`vouch-demo/${recoveryPhrase.trim()}`);
      const resp = await walletCreate(
        { h_passport_hex: hPassportHex },
        { baseUrl: signerUrl }
      );
      await saveAccount({ address: resp.account_address, pubX: resp.pub_x_hex });
      await saveSignerUrl(signerUrl);
      navigation.replace("Wallet");
    } catch (err) {
      Alert.alert("Setup failed", err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>vouch</Text>
      <Text style={styles.subtitle}>
        Create a 2-of-2 wallet. v0 demo: the signer service holds both shares;
        v1 brings the device's share over the UniFFI bridge. The onchain wallet
        is real either way.
      </Text>

      <View style={styles.fieldGroup}>
        <Text style={styles.label}>Signer URL</Text>
        <TextInput
          style={styles.input}
          value={signerUrl}
          onChangeText={setSignerUrl}
          autoCapitalize="none"
          autoCorrect={false}
        />

        <Text style={styles.label}>Recovery phrase (any string)</Text>
        <TextInput
          style={styles.input}
          value={recoveryPhrase}
          onChangeText={setRecoveryPhrase}
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="e.g. yellow-mountain-29"
        />
        <Text style={styles.helper}>
          Demo stand-in for the passport commitment. The real Recover screen
          re-derives it from your passport's MRZ over NFC.
        </Text>
      </View>

      <TouchableOpacity
        style={[styles.button, busy && styles.buttonDisabled]}
        onPress={onCreate}
        disabled={busy}
      >
        {busy ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.buttonText}>Create wallet</Text>
        )}
      </TouchableOpacity>

      <TouchableOpacity onPress={() => navigation.navigate("Recover")}>
        <Text style={styles.secondary}>I have a passport, recover an existing wallet →</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 24,
    justifyContent: "center",
    backgroundColor: "#fff",
    gap: 12,
  },
  title: { fontSize: 36, fontWeight: "700" },
  subtitle: { fontSize: 14, color: "#555", lineHeight: 20 },
  fieldGroup: { gap: 8, marginTop: 24 },
  label: { fontSize: 12, color: "#888", fontWeight: "600", textTransform: "uppercase" },
  helper: { fontSize: 12, color: "#666", marginTop: -4, fontStyle: "italic" },
  input: {
    borderWidth: 1,
    borderColor: "#ddd",
    borderRadius: 8,
    padding: 12,
    fontSize: 14,
    fontFamily: "Menlo",
  },
  button: {
    backgroundColor: "#000",
    padding: 16,
    borderRadius: 8,
    alignItems: "center",
    marginTop: 24,
  },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: "#fff", fontWeight: "600" },
  secondary: { color: "#0a7", textAlign: "center", marginTop: 8 },
});
