export type FlowStatus = 'waiting' | 'completed' | 'rejected' | 'expired' | 'failed';

export interface FlowState {
  status: FlowStatus;
  claims: Record<string, unknown> | null;
  at: string | null;
  /** Technischer Ablehnungscode, z. B. `issuer_certificate_revoked`. */
  error: string | null;
  message: string;
}

export declare const USER_MESSAGES: Record<'waiting' | 'completed' | 'rejected' | 'expired' | 'failed' | 'unknown', string>;
export declare const REJECTION_REASONS: Record<string, string>;
export declare function rejectionReason(code: unknown): string | null;
export declare function safeReturnUrl(raw: unknown): string | null;
export declare function createFlowState(): FlowState;
export declare function applyPollResponse(prev: FlowState, statusCode: number, body: unknown): FlowState;
