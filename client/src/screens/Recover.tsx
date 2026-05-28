import { useEffect, useState } from "react";
import {
  ActivityIndicator,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import { nfcSupported, scanPassport } from "../lib/passport";
import type { PassportReadResult } from "../lib/passport";
import type { RootStackParamList } from "../navigation";

type Props = NativeStackScreenProps<RootStackParamList, "Recover">;

type Stage = "mrz" | "scanning" | "done" | "error";

export function RecoverScreen({ navigation: _navigation }: Props) {
  const [docNumber, setDocNumber] = useState("");
  const [dob, setDob] = useState("");
  const [expiry, setExpiry] = useState("");
  const [stage, setStage] = useState<Stage>("mrz");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PassportReadResult | null>(null);
  const [nfcAvailable, setNfcAvailable] = useState<boolean | null>(null);

  useEffect(() => {
    (async () => setNfcAvailable(await nfcSupported()))();
  }, []);

  async function onTap() {
    setError(null);
    setResult(null);
    setStage("scanning");
    try {
      const r = await scanPassport({
        documentNumber: docNumber.toUpperCase(),
        dateOfBirth: dob,
        dateOfExpiry: expiry,
      });
      setResult(r);
      setStage("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStage("error");
    }
  }

  const inputsReady = docNumber.length > 0 && dob.length === 6 && expiry.length === 6;
  const busy = stage === "scanning";

  return (
    <ScrollView contentContainerStyle={styles.container} keyboardShouldPersistTaps="handled">
      <Text style={styles.title}>Recover from passport</Text>
      <Text style={styles.subtitle}>
        Enter the three MRZ values, then hold your passport flat against the back of
        your phone. BAC runs over NFC, DG1 is read, the commitment is computed
        on-device, and the result is sent to the signer. Your name and document number
        never leave the device.
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
          editable={!busy}
        />

        <Text style={styles.label}>Date of birth (YYMMDD)</Text>
        <TextInput
          style={styles.input}
          value={dob}
          onChangeText={setDob}
          placeholder="900115"
          keyboardType="number-pad"
          maxLength={6}
          editable={!busy}
        />

        <Text style={styles.label}>Expiry date (YYMMDD)</Text>
        <TextInput
          style={styles.input}
          value={expiry}
          onChangeText={setExpiry}
          placeholder="320615"
          keyboardType="number-pad"
          maxLength={6}
          editable={!busy}
        />
      </View>

      <TouchableOpacity
        style={[styles.button, (!inputsReady || busy) && styles.buttonDisabled]}
        onPress={onTap}
        disabled={!inputsReady || busy}
      >
        {busy ? (
          <View style={styles.row}>
            <ActivityIndicator color="#fff" />
            <Text style={styles.buttonText}>Hold passport near phone…</Text>
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

      {result && (
        <View style={styles.resultBox}>
          <Text style={styles.section}>Read</Text>

          <Text style={styles.label}>Name</Text>
          <Text style={styles.mono}>
            {result.mrz.primaryIdentifier}, {result.mrz.secondaryIdentifier}
          </Text>

          <Text style={styles.label}>Country / nationality</Text>
          <Text style={styles.mono}>
            {result.mrz.issuingCountry} / {result.mrz.nationality}
          </Text>

          <Text style={styles.label}>Date of birth</Text>
          <Text style={styles.mono}>{result.mrz.dateOfBirth}</Text>

          <Text style={styles.label}>Document number</Text>
          <Text style={styles.mono}>{result.mrz.documentNumber}</Text>

          <Text style={styles.label}>H_passport (will be sent to signer)</Text>
          <Text style={styles.mono} selectable>
            0x{result.hPassportHex}
          </Text>

          <Text style={styles.note}>
            TODO: POST this commitment + a new device pubkey to the signer's
            /v0/recover endpoint, run a fresh DKG, rotate the SCA's pubX.
          </Text>
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 24, backgroundColor: "#fff", gap: 16 },
  title: { fontSize: 28, fontWeight: "700" },
  subtitle: { fontSize: 14, color: "#555", lineHeight: 20 },
  warning: { padding: 12, backgroundColor: "#fff4d4", borderRadius: 8 },
  warningText: { color: "#7a5b00", fontSize: 13 },
  fieldGroup: { gap: 8, marginTop: 12 },
  label: { fontSize: 12, color: "#888", fontWeight: "600", textTransform: "uppercase" },
  mono: { fontFamily: "Menlo", fontSize: 12, color: "#222" },
  section: { fontSize: 16, fontWeight: "600", marginTop: 4, marginBottom: 8 },
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
    marginTop: 16,
  },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: "#fff", fontWeight: "600" },
  row: { flexDirection: "row", gap: 12, alignItems: "center" },
  errorBox: { padding: 12, backgroundColor: "#ffe5e5", borderRadius: 8 },
  errorText: { color: "#a01a1a", fontSize: 13, fontFamily: "Menlo" },
  resultBox: { padding: 16, backgroundColor: "#f5f5f5", borderRadius: 8, gap: 4 },
  note: {
    marginTop: 12,
    padding: 8,
    backgroundColor: "#e8f0ff",
    borderRadius: 4,
    fontSize: 11,
    color: "#1a3a7a",
    fontFamily: "Menlo",
  },
});
