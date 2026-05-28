import { useEffect, useState } from "react";
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

import { nfcSupported, scanPassportAndProve } from "../lib/passport";
import type { RootStackParamList } from "../navigation";

type Props = NativeStackScreenProps<RootStackParamList, "Recover">;

type Stage = "mrz" | "scanning" | "proving" | "submitting" | "done" | "error";

export function RecoverScreen({ navigation }: Props) {
  const [docNumber, setDocNumber] = useState("");
  const [dob, setDob] = useState(""); // YYMMDD
  const [expiry, setExpiry] = useState(""); // YYMMDD
  const [stage, setStage] = useState<Stage>("mrz");
  const [error, setError] = useState<string | null>(null);
  const [nfcAvailable, setNfcAvailable] = useState<boolean | null>(null);

  useEffect(() => {
    (async () => setNfcAvailable(await nfcSupported()))();
  }, []);

  async function onTap() {
    setError(null);
    setStage("scanning");
    try {
      const proof = await scanPassportAndProve({
        mrz: { documentNumber: docNumber.toUpperCase(), dateOfBirth: dob, expiryDate: expiry },
        challenge: `recover-${Date.now()}`,
      });
      setStage("submitting");
      // TODO: POST proof to signer's /v0/recover endpoint, get new
      // joint pubkey + new device share, save, then navigate to Wallet.
      throw new Error("signer /v0/recover not implemented yet");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStage("error");
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Recover from passport</Text>
      <Text style={styles.subtitle}>
        Enter the three values from your passport MRZ so we can authenticate to
        the chip, then tap your passport to the back of your phone. The proof
        is generated on-device; your name, country and document number never
        leave your phone.
      </Text>

      {nfcAvailable === false && (
        <View style={styles.warning}>
          <Text style={styles.warningText}>NFC is unavailable on this device.</Text>
        </View>
      )}

      <View style={styles.fieldGroup}>
        <Text style={styles.label}>Document number</Text>
        <TextInput
          style={styles.input}
          value={docNumber}
          onChangeText={setDocNumber}
          placeholder="XX1234567"
          autoCapitalize="characters"
          autoCorrect={false}
        />

        <Text style={styles.label}>Date of birth (YYMMDD)</Text>
        <TextInput
          style={styles.input}
          value={dob}
          onChangeText={setDob}
          placeholder="900115"
          keyboardType="number-pad"
          maxLength={6}
        />

        <Text style={styles.label}>Expiry date (YYMMDD)</Text>
        <TextInput
          style={styles.input}
          value={expiry}
          onChangeText={setExpiry}
          placeholder="320615"
          keyboardType="number-pad"
          maxLength={6}
        />
      </View>

      <TouchableOpacity
        style={[styles.button, stage !== "mrz" && stage !== "error" && styles.buttonDisabled]}
        onPress={onTap}
        disabled={stage !== "mrz" && stage !== "error"}
      >
        {stage === "scanning" || stage === "proving" || stage === "submitting" ? (
          <View style={styles.row}>
            <ActivityIndicator color="#fff" />
            <Text style={styles.buttonText}>
              {stage === "scanning"
                ? "Hold passport near phone…"
                : stage === "proving"
                  ? "Generating proof…"
                  : "Submitting to signer…"}
            </Text>
          </View>
        ) : (
          <Text style={styles.buttonText}>Tap passport</Text>
        )}
      </TouchableOpacity>

      {error && (
        <View style={styles.errorBox}>
          <Text style={styles.errorText}>{error}</Text>
        </View>
      )}

      <TouchableOpacity onPress={() => navigation.goBack()}>
        <Text style={styles.secondary}>← Back</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, backgroundColor: "#fff", gap: 16 },
  title: { fontSize: 28, fontWeight: "700" },
  subtitle: { fontSize: 14, color: "#555", lineHeight: 20 },
  warning: { padding: 12, backgroundColor: "#fff4d4", borderRadius: 8 },
  warningText: { color: "#7a5b00", fontSize: 13 },
  fieldGroup: { gap: 8, marginTop: 12 },
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
  buttonDisabled: { opacity: 0.5 },
  buttonText: { color: "#fff", fontWeight: "600" },
  row: { flexDirection: "row", gap: 12, alignItems: "center" },
  errorBox: {
    marginTop: 8,
    padding: 12,
    backgroundColor: "#ffe5e5",
    borderRadius: 8,
  },
  errorText: { color: "#a01a1a", fontSize: 13 },
  secondary: { color: "#0a7", textAlign: "center", marginTop: 16 },
});
