// HTTP client for the vouch-signer service.
//
// v0 demo uses the /v0/wallet/* endpoints — server holds the FROST
// shares, signs in-process, submits onchain. The threshold story lives
// behind the older /v0/{dkg,sign,recover} endpoints and ships in v1.

const DEFAULT_BASE = "http://localhost:8089";

export type SignerConfig = { baseUrl?: string };

function url(path: string, cfg?: SignerConfig): string {
  return `${cfg?.baseUrl ?? DEFAULT_BASE}${path}`;
}

async function post<Req, Resp>(
  path: string,
  body: Req,
  cfg?: SignerConfig
): Promise<Resp> {
  const res = await fetch(url(path, cfg), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`signer ${path} failed: ${res.status} ${await res.text()}`);
  }
  return (await res.json()) as Resp;
}

// ───── v0 wallet endpoints ───────────────────────────────────────────────

export type WalletCreateRequest = { h_passport_hex: string };
export type WalletCreateResponse = {
  account_address: string;
  pub_x_hex: string;
  deploy_tx_hash: string | null;
};

export type WalletSignExecuteRequest = {
  account_address: string;
  target: string;
  value: string;
  data: string;
};
export type WalletSignExecuteResponse = {
  tx_hash: string;
  op_hash_hex: string;
  signature_hex: string;
};

export type WalletRecoverRequest = { h_passport_hex: string };
export type WalletRecoverResponse = {
  account_address: string;
  old_pub_x_hex: string;
  new_pub_x_hex: string;
  rotation_tx_hash: string;
};

export const walletCreate = (req: WalletCreateRequest, cfg?: SignerConfig) =>
  post<WalletCreateRequest, WalletCreateResponse>("/v0/wallet/create", req, cfg);

export const walletSignExecute = (req: WalletSignExecuteRequest, cfg?: SignerConfig) =>
  post<WalletSignExecuteRequest, WalletSignExecuteResponse>(
    "/v0/wallet/sign-and-execute",
    req,
    cfg
  );

export const walletRecover = (req: WalletRecoverRequest, cfg?: SignerConfig) =>
  post<WalletRecoverRequest, WalletRecoverResponse>("/v0/wallet/recover", req, cfg);
