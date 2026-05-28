import { useEffect, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import { runClientSign } from "../lib/frost";
import { loadAccount, loadShare } from "../lib/storage";
import type { RootStackParamList } from "../navigation";

type Props = NativeStackScreenProps<RootStackParamList, "Wallet">;

export function WalletScreen({ navigation }: Props) {
  const [pubX, setPubX] = useState<string | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [target, setTarget] = useState("0xCAFE000000000000000000000000000000000000");
  const [data, setData] = useState("0x");
  const [busy, setBusy] = useState(false);
  const [lastSig, setLastSig] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const acct = await loadAccount();
      if (!acct) {
        navigation.replace("Onboarding");
        return;
      }
      setPubX(acct.pubX);
      setAddress(acct.address);
    })();
  }, [navigation]);

  async function onSign() {
    if (!pubX) return;
    setBusy(true);
    try {
      const share = await loadShare();
      if (!share) throw new Error("device share missing — re-onboard or recover");

      // For the demo, the "op hash" is just keccak(target || data) — the
      // production version is the SCA's opHash() that binds chainid + account.
      // Without a JS keccak in this stub, just sign a deterministic 32-byte
      // mock. Real wiring lands when the SCA is in the loop.
      const mockOpHash = "0".repeat(64);

      const sig = await runClientSign({
        relayUrl: "ws://localhost:8088/ws",
        signerUrl: "http://localhost:8089",
        sessionId: `sign-${Date.now()}`,
        clientParticipant: 1,
        signerParticipant: 2,
        share,
        pubX,
        opHash: mockOpHash,
      });
      setLastSig(sig);
    } catch (err) {
      Alert.alert("Sign failed", err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.label}>Joint pubkey</Text>
      <Text style={styles.mono} selectable>
        {pubX ?? "—"}
      </Text>

      <Text style={styles.label}>Address</Text>
      <Text style={styles.mono} selectable>
        {address || "(not yet deployed)"}
      </Text>

      <View style={styles.spacer} />

      <Text style={styles.section}>Sign a userop</Text>

      <Text style={styles.label}>Target</Text>
      <TextInput
        style={styles.input}
        value={target}
        onChangeText={setTarget}
        autoCapitalize="none"
        autoCorrect={false}
      />

      <Text style={styles.label}>Call data</Text>
      <TextInput
        style={styles.input}
        value={data}
        onChangeText={setData}
        autoCapitalize="none"
        autoCorrect={false}
      />

      <TouchableOpacity
        style={[styles.button, busy && styles.buttonDisabled]}
        onPress={onSign}
        disabled={busy}
      >
        {busy ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.buttonText}>Sign + execute</Text>
        )}
      </TouchableOpacity>

      {lastSig && (
        <View style={styles.sigBox}>
          <Text style={styles.label}>Last signature</Text>
          <Text style={styles.mono} selectable>
            {lastSig}
          </Text>
        </View>
      )}

      <TouchableOpacity onPress={() => navigation.navigate("Recover")}>
        <Text style={styles.secondary}>Lost your device? Recover from passport →</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 24, gap: 12, backgroundColor: "#fff" },
  label: { fontSize: 12, color: "#888", fontWeight: "600", textTransform: "uppercase" },
  mono: { fontFamily: "Menlo", fontSize: 11, color: "#333" },
  section: { fontSize: 18, fontWeight: "600", marginTop: 8 },
  input: {
    borderWidth: 1,
    borderColor: "#ddd",
    borderRadius: 8,
    padding: 12,
    fontSize: 13,
    fontFamily: "Menlo",
  },
  button: {
    backgroundColor: "#000",
    padding: 16,
    borderRadius: 8,
    alignItems: "center",
    marginTop: 16,
  },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: "#fff", fontWeight: "600" },
  sigBox: { marginTop: 16, padding: 12, backgroundColor: "#f5f5f5", borderRadius: 8 },
  secondary: { color: "#0a7", textAlign: "center", marginTop: 24 },
  spacer: { height: 8 },
});
