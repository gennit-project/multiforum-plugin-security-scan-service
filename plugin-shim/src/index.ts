/**
 * security-attachment-scan — Multiforum plugin (thin shim).
 *
 * Multiforum plugins run in-process inside the Node backend. This shim does no
 * scanning itself: on a `downloadableFile.*` event it forwards each attachment
 * URL to the standalone Python security-scan service and maps the response back
 * into a PluginRunResult.
 *
 * Contract (verified against the backend's downloadTrigger.ts):
 *   - constructor receives `context` with `settings`, `secrets.server`, `log`
 *   - `handleEvent({ type, payload })` where payload.attachmentUrls is string[]
 *   - returns `{ success, error?, result?: { message?, ...extra } }`
 */

type PluginContext = {
  scope: 'SERVER' | 'CHANNEL';
  channelId: string;
  settings: Record<string, unknown>;
  secrets: { server: Record<string, string> };
  log: (...args: unknown[]) => void;
};

type EventEnvelope = {
  type: string;
  payload: {
    attachmentUrls?: string[];
    downloadableFileId?: string;
    [key: string]: unknown;
  };
};

type PluginRunResult = {
  success?: boolean;
  error?: string;
  result?: { message?: string } & Record<string, unknown>;
};

type ScanVerdict = 'clean' | 'suspicious' | 'malicious' | 'error';

type ScanResult = {
  verdict: ScanVerdict;
  summary: string;
  sha256?: string;
  checks?: unknown[];
};

const VERDICT_SEVERITY: Record<ScanVerdict, number> = {
  clean: 0,
  suspicious: 1,
  malicious: 2,
  error: 3,
};

export default class SecurityAttachmentScanPlugin {
  private ctx: PluginContext;

  constructor(context: PluginContext) {
    this.ctx = context;
  }

  async handleEvent(envelope: EventEnvelope): Promise<PluginRunResult> {
    const { settings, secrets, log } = this.ctx;

    const serviceUrl = String(settings.serviceUrl || '').replace(/\/+$/, '');
    const apiKey = secrets.server?.apiKey || '';
    if (!serviceUrl) {
      return { success: false, error: 'security-attachment-scan: serviceUrl is not configured.' };
    }

    const urls = envelope.payload?.attachmentUrls ?? [];
    if (urls.length === 0) {
      return { success: true, result: { message: 'No attachments to scan.' } };
    }

    // `blockOn` decides which verdict fails the pipeline step. Default: block
    // only on malicious so a missing README (suspicious) does not hard-fail.
    const blockOn = (String(settings.blockOn || 'malicious') as ScanVerdict);
    const policy = (settings.policy as Record<string, unknown>) ?? {};

    const results: ScanResult[] = [];
    for (const fileUrl of urls) {
      try {
        const scan = await this.scanOne({ serviceUrl, apiKey, fileUrl, policy });
        results.push(scan);
        log(`security-attachment-scan: ${fileUrl} → ${scan.verdict} (${scan.summary})`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log(`security-attachment-scan: request failed for ${fileUrl}: ${message}`);
        results.push({ verdict: 'error', summary: message });
      }
    }

    const worst = results.reduce<ScanVerdict>(
      (acc, r) => (VERDICT_SEVERITY[r.verdict] > VERDICT_SEVERITY[acc] ? r.verdict : acc),
      'clean',
    );

    const blocked = VERDICT_SEVERITY[worst] >= VERDICT_SEVERITY[blockOn];
    const summary = results.map((r) => `${r.verdict}: ${r.summary}`).join(' | ');

    return {
      success: !blocked,
      error: blocked ? `Attachment scan blocked upload: ${summary}` : undefined,
      result: {
        message: blocked ? `Blocked (${worst}).` : `Passed (${worst}).`,
        verdict: worst,
        scans: results,
      },
    };
  }

  private async scanOne(args: {
    serviceUrl: string;
    apiKey: string;
    fileUrl: string;
    policy: Record<string, unknown>;
  }): Promise<ScanResult> {
    const { serviceUrl, apiKey, fileUrl, policy } = args;
    const response = await fetch(`${serviceUrl}/scan`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
      },
      body: JSON.stringify({ file_url: fileUrl, policy }),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`scan service returned HTTP ${response.status}: ${text.slice(0, 200)}`);
    }

    return (await response.json()) as ScanResult;
  }
}
