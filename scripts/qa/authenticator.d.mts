export declare class SoftwareAuthenticator {
  credentials: Map<string, unknown>;
  register(options: unknown, origin: string): Promise<Record<string, unknown> & { id: string }>;
  authenticate(options: unknown, origin: string, credentialId?: string): Promise<Record<string, unknown> & { id: string }>;
  export(): Promise<unknown[]>;
  static import(entries: unknown[]): Promise<SoftwareAuthenticator>;
}
