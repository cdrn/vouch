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

import { walletSignExecute } from "../lib/signer";
import { clearAccount, loadAccount, loadSignerUrl } from "../lib/storage";
import type { RootStackParamList } from "../navigation";

type Props = NativeStackScreenProps<RootStackParamList, "Wallet">;

export function WalletScreen({ navigation }: Props) {
  const [address, setAddress] = useState<string | null>(null);
  const [pubX, setPubX] = useState<string | null>(null);
  const [signerUrl, setSignerUrl] = useState<string | null>(null);

  const [target, setTarget] = useState("0xCAFE000000000000000000000000000000000000");
  const [value, setValue] = useState("0");
  const [data, setData] = useState("0x");

  const [busy, setBusy] = useState(false);
  const [lastTxHash, setLastTxHash] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const acct = await loadAccount();
      if (!acct) {
        navigation.replace("Onboarding");
        return;
      }
      setAddress(acct.address);
      setPubX(acct.pubX);
      setSignerUrl(await loadSignerUrl());
    })();
  }, [navigation]);

  async function onSignExecute() {
    if (!address || !signerUrl) return;
    setBusy(true);
    setLastTxHash(null);
    try {
      const resp = await walletSignExecute(
        { account_address: address, target, value, data },
        { baseUrl: signerUrl }
      );
      setLastTxHash(resp.tx_hash);
    } catch (err) {
      Alert.alert("Sign failed", err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onSignOut() {
    await clearAccount();
    navigation.replace("Onboarding");
  }

  return (
    <ScrollView contentContainerStyle={styles.container} keyboardShouldPersistTaps="handled">
      <Text style={styles.label}>Account address</Text>
      <Text style={styles.mono} selectable>
        {address ?? "—"}
      </Text>

      <Text style={styles.label}>Joint pubkey (BIP340 x-only)</Text>
      <Text style={styles.mono} selectable>
        {pubX ? `0x${pubX}` : "—"}
      </Text>

      <View style={styles.spacer} />
      <Text style={styles.section}>Sign + execute a userop</Text>

      <Text style={styles.label}>Target address</Text>
      <TextInput
        style={styles.input}
        value={target}
        onChangeText={setTarget}
        autoCapitalize="none"
        autoCorrect={false}
        editable={!busy}
      />

      <Text style={styles.label}>Value (wei, decimal)</Text>
      <TextInput
        style={styles.input}
        value={value}
        onChangeText={setValue}
        keyboardType="number-pad"
        editable={!busy}
      />

      <Text style={styles.label}>Call data (hex)</Text>
      <TextInput
        style={styles.input}
        value={data}
        onChangeText={setData}
        autoCapitalize="none"
        autoCorrect={false}
        editable={!busy}
      />

      <TouchableOpacity
        style={[styles.button, busy && styles.buttonDisabled]}
        onPress={onSignExecute}
        disabled={busy}
      >
        {busy ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.buttonText}>Sign + execute</Text>
        )}
      </TouchableOpacity>

      {lastTxHash && (
        <View style={styles.txBox}>
          <Text style={styles.label}>Transaction hash</Text>
          <Text style={styles.mono} selectable>
            {lastTxHash}
          </Text>
        </View>
      )}

      <View style={styles.spacer} />

      <TouchableOpacity onPress={() => navigation.navigate("Recover")}>
        <Text style={styles.secondary}>Lost your device? Recover from passport →</Text>
      </TouchableOpacity>

      <TouchableOpacity onPress={onSignOut}>
        <Text style={styles.danger}>Sign out (clear local account)</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 24, gap: 8, backgroundColor: "#fff" },
  label: { fontSize: 12, color: "#888", fontWeight: "600", textTransform: "uppercase" },
  mono: { fontFamily: "Menlo", fontSize: 11, color: "#222" },
  section: { fontSize: 18, fontWeight: "600", marginTop: 12 },
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
    marginTop: 12,
  },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: "#fff", fontWeight: "600" },
  txBox: { marginTop: 12, padding: 12, backgroundColor: "#eef9f0", borderRadius: 8 },
  secondary: { color: "#0a7", textAlign: "center", marginTop: 16 },
  danger: { color: "#a01a1a", textAlign: "center", marginTop: 12, fontSize: 13 },
  spacer: { height: 8 },
});
