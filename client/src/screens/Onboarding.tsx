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

import { runClientDkg } from "../lib/frost";
import { saveAccount, saveShare } from "../lib/storage";
import type { RootStackParamList } from "../navigation";

type Props = NativeStackScreenProps<RootStackParamList, "Onboarding">;

const DEFAULT_RELAY = "ws://localhost:8088/ws";
const DEFAULT_SIGNER = "http://localhost:8089";

export function OnboardingScreen({ navigation }: Props) {
  const [relayUrl, setRelayUrl] = useState(DEFAULT_RELAY);
  const [signerUrl, setSignerUrl] = useState(DEFAULT_SIGNER);
  const [busy, setBusy] = useState(false);

  async function onCreate() {
    setBusy(true);
    try {
      const sessionId = `dkg-${Date.now()}`;
      const { pubX, share } = await runClientDkg({
        relayUrl,
        signerUrl,
        sessionId,
        clientParticipant: 1,
        signerParticipant: 2,
      });
      await saveShare(share);
      // For v0 the account address is derived later (CREATE2 from pubX).
      // Use a placeholder until the deploy step is wired.
      await saveAccount(pubX, "");
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
        Create a 2-of-2 wallet. Your device holds one share; the signer service
        holds the other. Neither can sign alone.
      </Text>

      <View style={styles.fieldGroup}>
        <Text style={styles.label}>Relay URL</Text>
        <TextInput
          style={styles.input}
          value={relayUrl}
          onChangeText={setRelayUrl}
          autoCapitalize="none"
          autoCorrect={false}
        />

        <Text style={styles.label}>Signer URL</Text>
        <TextInput
          style={styles.input}
          value={signerUrl}
          onChangeText={setSignerUrl}
          autoCapitalize="none"
          autoCorrect={false}
        />
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
    gap: 16,
  },
  title: { fontSize: 36, fontWeight: "700" },
  subtitle: { fontSize: 14, color: "#555", lineHeight: 20 },
  fieldGroup: { gap: 8, marginTop: 24 },
  label: { fontSize: 12, color: "#888", fontWeight: "600", textTransform: "uppercase" },
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
