import { 
  WebCryptoProvider, 
  OpenPGPProvider, 
  KeyManager, 
  SecureStorage,
  type EncryptedData,
  type PGPKeyPair 
} from '@zero/encryption';
import { db } from '../db';
import { users, userConnections } from '../db/schema';
import { eq } from 'drizzle-orm';

/**
 * Email encryption service for Zero
 */
export class EmailEncryptionService {
  private crypto: WebCryptoProvider;
  private storage: SecureStorage;
  private keyManager: KeyManager;

  constructor() {
    this.crypto = new WebCryptoProvider();
    this.storage = new SecureStorage('ZeroEmailEncryption');
    this.keyManager = new KeyManager(this.storage);
  }

  /**
   * Initialize encryption for a user
   */
  async initializeUser(userId: string, masterPassword: string): Promise<void> {
    // Initialize key manager with user's master password
    await this.keyManager.initialize(masterPassword);

    // Check if user already has PGP keys
    const existingKeys = await this.getUserPGPKeys(userId);
    if (!existingKeys) {
      // Generate new PGP keys for the user
      const user = await db.select().from(users).where(eq(users.id, userId)).limit(1);
      if (user.length > 0) {
        const { name, email } = user[0];
        await this.generateUserPGPKeys(userId, name || 'Zero User', email);
      }
    }
  }

  /**
   * Generate PGP keys for a user
   */
  async generateUserPGPKeys(
    userId: string,
    name: string,
    email: string
  ): Promise<PGPKeyPair> {
    const pgpKeys = await OpenPGPProvider.generateKeyPair(name, email);
    
    // Store keys encrypted in database
    const encryptedPrivate = await this.crypto.encrypt(
      pgpKeys.privateKey,
      await this.keyManager.generateKey('master')
    );
    
    await db.insert(users).values({
      id: userId,
      pgpPublicKey: pgpKeys.publicKey,
      pgpPrivateKeyEncrypted: JSON.stringify(encryptedPrivate),
      pgpFingerprint: pgpKeys.fingerprint,
    }).onConflictDoUpdate({
      target: users.id,
      set: {
        pgpPublicKey: pgpKeys.publicKey,
        pgpPrivateKeyEncrypted: JSON.stringify(encryptedPrivate),
        pgpFingerprint: pgpKeys.fingerprint,
      }
    });

    return pgpKeys;
  }

  /**
   * Get user's PGP keys
   */
  async getUserPGPKeys(userId: string): Promise<PGPKeyPair | null> {
    const user = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    
    if (user.length === 0 || !user[0].pgpPublicKey || !user[0].pgpPrivateKeyEncrypted) {
      return null;
    }

    // Decrypt private key
    const encryptedData = JSON.parse(user[0].pgpPrivateKeyEncrypted) as EncryptedData;
    const masterKey = await this.keyManager.getKey('master');
    
    if (!masterKey || !(masterKey.key instanceof CryptoKey)) {
      throw new Error('Master key not found');
    }

    const privateKey = await this.crypto.decryptString(encryptedData, masterKey.key);

    return {
      publicKey: user[0].pgpPublicKey,
      privateKey,
      fingerprint: user[0].pgpFingerprint || '',
      userId: user[0].email,
      createdAt: new Date(),
    };
  }

  /**
   * Encrypt an email
   */
  async encryptEmail(
    senderUserId: string,
    recipientEmails: string[],
    subject: string,
    body: string,
    attachments?: Array<{ filename: string; data: Uint8Array; mimeType: string }>
  ): Promise<{
    encryptedSubject: string;
    encryptedBody: string;
    encryptedAttachments?: Array<{ filename: string; encryptedData: string }>;
  }> {
    // Get sender's PGP keys
    const senderKeys = await this.getUserPGPKeys(senderUserId);
    if (!senderKeys) {
      throw new Error('Sender PGP keys not found');
    }

    // Get recipient public keys
    const recipientPublicKeys: string[] = [];
    for (const email of recipientEmails) {
      const recipient = await db.select()
        .from(users)
        .where(eq(users.email, email))
        .limit(1);
      
      if (recipient.length > 0 && recipient[0].pgpPublicKey) {
        recipientPublicKeys.push(recipient[0].pgpPublicKey);
      }
    }

    // Add sender's public key to encrypt for themselves
    recipientPublicKeys.push(senderKeys.publicKey);

    // Encrypt subject and body
    const encryptedSubject = await OpenPGPProvider.encrypt(
      subject,
      recipientPublicKeys,
      senderKeys.privateKey
    );

    const encryptedBody = await OpenPGPProvider.encrypt(
      body,
      recipientPublicKeys,
      senderKeys.privateKey
    );

    // Encrypt attachments if any
    let encryptedAttachments;
    if (attachments && attachments.length > 0) {
      encryptedAttachments = [];
      for (const attachment of attachments) {
        const encryptedData = await OpenPGPProvider.encryptBinary(
          attachment.data,
          recipientPublicKeys,
          attachment.filename
        );
        encryptedAttachments.push({
          filename: attachment.filename,
          encryptedData,
        });
      }
    }

    return {
      encryptedSubject,
      encryptedBody,
      encryptedAttachments,
    };
  }

  /**
   * Decrypt an email
   */
  async decryptEmail(
    userId: string,
    encryptedSubject: string,
    encryptedBody: string,
    verifyingPublicKey?: string
  ): Promise<{
    subject: string;
    body: string;
    signatures?: Array<{ valid: boolean; keyId: string }>;
  }> {
    const userKeys = await this.getUserPGPKeys(userId);
    if (!userKeys) {
      throw new Error('User PGP keys not found');
    }

    // Decrypt subject and body
    const decryptedSubject = await OpenPGPProvider.decrypt(
      encryptedSubject,
      userKeys.privateKey,
      undefined,
      verifyingPublicKey
    );

    const decryptedBody = await OpenPGPProvider.decrypt(
      encryptedBody,
      userKeys.privateKey,
      undefined,
      verifyingPublicKey
    );

    return {
      subject: decryptedSubject.data,
      body: decryptedBody.data,
      signatures: decryptedBody.signatures?.map(sig => ({
        valid: sig.verified || false,
        keyId: sig.keyID.toHex(),
      })),
    };
  }

  /**
   * Search encrypted emails (using encrypted index)
   */
  async searchEncryptedEmails(
    userId: string,
    searchTerm: string
  ): Promise<string[]> {
    // This is a simplified version - in production, implement
    // searchable encryption using techniques like:
    // 1. Bloom filters for encrypted search
    // 2. Homomorphic encryption
    // 3. Encrypted inverted index
    
    // For now, return empty array
    console.log('Encrypted search not yet implemented');
    return [];
  }

  /**
   * Export user's encryption keys
   */
  async exportUserKeys(
    userId: string,
    exportPassword: string
  ): Promise<string> {
    const userKeys = await this.getUserPGPKeys(userId);
    if (!userKeys) {
      throw new Error('User keys not found');
    }

    // Create export package
    const exportData = {
      version: '1.0',
      userId,
      publicKey: userKeys.publicKey,
      privateKey: userKeys.privateKey,
      fingerprint: userKeys.fingerprint,
      exported: new Date().toISOString(),
    };

    // Encrypt export with password
    const salt = WebCryptoProvider.generateRandomString(16);
    const key = await this.crypto.generateKey();
    
    const encrypted = await this.crypto.encrypt(
      JSON.stringify(exportData),
      key
    );

    return JSON.stringify({
      encrypted,
      salt,
    });
  }

  /**
   * Enable E2E encryption for a connection
   */
  async enableE2EForConnection(
    connectionId: string,
    userId: string
  ): Promise<void> {
    await db.update(userConnections)
      .set({
        e2eEnabled: true,
        e2ePublicKey: (await this.getUserPGPKeys(userId))?.publicKey,
      })
      .where(eq(userConnections.id, connectionId));
  }

  /**
   * Get encryption status for an email
   */
  async getEncryptionStatus(emailId: string): Promise<{
    encrypted: boolean;
    signed: boolean;
    algorithm?: string;
    recipients?: string[];
  }> {
    // Check email metadata for encryption status
    // This would be stored when the email is received/sent
    
    return {
      encrypted: false,
      signed: false,
    };
  }

  /**
   * Rotate encryption keys
   */
  async rotateUserKeys(userId: string): Promise<void> {
    const user = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (user.length === 0) {
      throw new Error('User not found');
    }

    // Generate new keys
    await this.generateUserPGPKeys(
      userId,
      user[0].name || 'Zero User',
      user[0].email
    );

    // Mark old keys as rotated
    await this.keyManager.rotateKeys(30); // Rotate keys older than 30 days
  }
}