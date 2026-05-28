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

import { nfcSupported, scanPassport, type PassportReadResult } from "../lib/passport";
import { walletRecover } from "../lib/signer";
import { loadSignerUrl, saveAccount } from "../lib/storage";
import type { RootStackParamList } from "../navigation";

type Props = NativeStackScreenProps<RootStackParamList, "Recover">;

type Stage = "mrz" | "scanning" | "submitting" | "done" | "error";

export function RecoverScreen({ navigation }: Props) {
  const [docNumber, setDocNumber] = useState("");
  const [dob, setDob] = useState("");
  const [expiry, setExpiry] = useState("");
  const [stage, setStage] = useState<Stage>("mrz");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PassportReadResult | null>(null);
  const [rotationTxHash, setRotationTxHash] = useState<string | null>(null);
  const [newPubX, setNewPubX] = useState<string | null>(null);
  const [accountAddress, setAccountAddress] = useState<string | null>(null);
  const [nfcAvailable, setNfcAvailable] = useState<boolean | null>(null);
  const [signerUrl, setSignerUrlState] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setNfcAvailable(await nfcSupported());
      setSignerUrlState(await loadSignerUrl());
    })();
  }, []);

  async function onTap() {
    setError(null);
    setResult(null);
    setRotationTxHash(null);
    setStage("scanning");
    try {
      const r = await scanPassport({
        documentNumber: docNumber.toUpperCase(),
        dateOfBirth: dob,
        dateOfExpiry: expiry,
      });
      setResult(r);
      setStage("submitting");

      const resp = await walletRecover(
        { h_passport_hex: r.hPassportHex },
        signerUrl ? { baseUrl: signerUrl } : undefined
      );

      setAccountAddress(resp.account_address);
      setNewPubX(resp.new_pub_x_hex);
      setRotationTxHash(resp.rotation_tx_hash);

      // Persist locally so the Wallet screen picks up the recovered account.
      await saveAccount({
        address: resp.account_address,
        pubX: resp.new_pub_x_hex,
      });
      setStage("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStage("error");
    }
  }

  const inputsReady = docNumber.length > 0 && dob.length === 6 && expiry.length === 6;
  const busy = stage === "scanning" || stage === "submitting";

  return (
    <ScrollView contentContainerStyle={styles.container} keyboardShouldPersistTaps="handled">
      <Text style={styles.title}>Recover from passport</Text>
      <Text style={styles.subtitle}>
        Enter the three MRZ values, then hold your passport flat against the back
        of your phone. BAC runs over NFC, DG1 is read, H_passport is computed
        on-device, and the signer rotates the SCA's pubkey onchain. Your name and
        document number never leave the device.
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
            <Text style={styles.buttonText}>
              {stage === "scanning"
                ? "Hold passport near phone…"
                : "Rotating onchain…"}
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

      {result && (
        <View style={styles.resultBox}>
          <Text style={styles.section}>Passport read</Text>

          <Text style={styles.label}>Name</Text>
          <Text style={styles.mono}>
            {result.mrz.primaryIdentifier}, {result.mrz.secondaryIdentifier}
          </Text>

          <Text style={styles.label}>Country / nationality</Text>
          <Text style={styles.mono}>
            {result.mrz.issuingCountry} / {result.mrz.nationality}
          </Text>

          <Text style={styles.label}>H_passport (sent to signer)</Text>
          <Text style={styles.mono} selectable>
            0x{result.hPassportHex}
          </Text>
        </View>
      )}

      {rotationTxHash && (
        <View style={styles.successBox}>
          <Text style={styles.section}>Recovered onchain</Text>
          <Text style={styles.label}>Account</Text>
          <Text style={styles.mono} selectable>
            {accountAddress}
          </Text>
          <Text style={styles.label}>New pubkey</Text>
          <Text style={styles.mono} selectable>
            0x{newPubX}
          </Text>
          <Text style={styles.label}>Rotation tx</Text>
          <Text style={styles.mono} selectable>
            {rotationTxHash}
          </Text>

          <TouchableOpacity
            style={styles.successButton}
            onPress={() => navigation.replace("Wallet")}
          >
            <Text style={styles.buttonText}>Open wallet</Text>
          </TouchableOpacity>
        </View>
      )}

      {stage !== "done" && (
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Text style={styles.secondary}>← Back</Text>
        </TouchableOpacity>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 24, backgroundColor: "#fff", gap: 12 },
  title: { fontSize: 28, fontWeight: "700" },
  subtitle: { fontSize: 14, color: "#555", lineHeight: 20 },
  warning: { padding: 12, backgroundColor: "#fff4d4", borderRadius: 8 },
  warningText: { color: "#7a5b00", fontSize: 13 },
  fieldGroup: { gap: 8, marginTop: 8 },
  label: { fontSize: 12, color: "#888", fontWeight: "600", textTransform: "uppercase" },
  mono: { fontFamily: "Menlo", fontSize: 11, color: "#222" },
  section: { fontSize: 16, fontWeight: "600", marginBottom: 8 },
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
  successBox: { padding: 16, backgroundColor: "#eef9f0", borderRadius: 8, gap: 4 },
  successButton: {
    backgroundColor: "#0a7",
    padding: 14,
    borderRadius: 8,
    alignItems: "center",
    marginTop: 12,
  },
  secondary: { color: "#0a7", textAlign: "center", marginTop: 12 },
});
