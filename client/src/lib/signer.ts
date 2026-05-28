// HTTP client for the vouch-signer service.

const DEFAULT_BASE = "http://localhost:8089";

export type SignerConfig = { baseUrl?: string };

function url(path: string, cfg?: SignerConfig): string {
  return `${cfg?.baseUrl ?? DEFAULT_BASE}${path}`;
}

export type DkgRequest = {
  session: string;
  relay_url: string;
  signer_participant: number;
  client_participant: number;
};

export type DkgResponse = {
  joint_pubkey_hex: string;
};

export async function startDkg(req: DkgRequest, cfg?: SignerConfig): Promise<DkgResponse> {
  const res = await fetch(url("/v0/dkg", cfg), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) throw new Error(`signer /v0/dkg failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as DkgResponse;
}

export type SignRequest = {
  account_pubkey_hex: string;
  session: string;
  relay_url: string;
  signer_participant: number;
  client_participant: number;
  message: number[]; // bytes
};

export type SignResponse = {
  signature_hex: string;
};

export async function startSign(req: SignRequest, cfg?: SignerConfig): Promise<SignResponse> {
  const res = await fetch(url("/v0/sign", cfg), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) throw new Error(`signer /v0/sign failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as SignResponse;
}
