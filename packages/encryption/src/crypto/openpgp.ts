import * as openpgp from 'openpgp';
import type { PGPKeyPair, EncryptedData } from '../types';
import { pgpKeyPairSchema } from '../schemas';

/**
 * OpenPGP integration for end-to-end email encryption
 */
export class OpenPGPProvider {
  /**
   * Generate a new PGP key pair
   */
  static async generateKeyPair(
    name: string,
    email: string,
    passphrase?: string
  ): Promise<PGPKeyPair> {
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: 'rsa',
      rsaBits: 4096,
      userIDs: [{ name, email }],
      passphrase,
      format: 'armored',
    });

    const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });
    const fingerprint = publicKeyObj.getFingerprint();

    return pgpKeyPairSchema.parse({
      publicKey,
      privateKey,
      fingerprint,
      userId: email,
      createdAt: new Date(),
    });
  }

  /**
   * Encrypt text with PGP
   */
  static async encrypt(
    text: string,
    recipientPublicKeys: string[],
    signingPrivateKey?: string,
    passphrase?: string
  ): Promise<string> {
    const publicKeys = await Promise.all(
      recipientPublicKeys.map(key => openpgp.readKey({ armoredKey: key }))
    );

    const encryptOptions: openpgp.EncryptOptions = {
      message: await openpgp.createMessage({ text }),
      encryptionKeys: publicKeys,
      format: 'armored',
    };

    // Add signing if private key provided
    if (signingPrivateKey) {
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: signingPrivateKey }),
        passphrase: passphrase || '',
      });
      encryptOptions.signingKeys = privateKey;
    }

    const encrypted = await openpgp.encrypt(encryptOptions);
    return encrypted as string;
  }

  /**
   * Decrypt PGP encrypted text
   */
  static async decrypt(
    encryptedText: string,
    privateKey: string,
    passphrase?: string,
    verifyingPublicKey?: string
  ): Promise<{
    data: string;
    signatures?: openpgp.VerificationResult[];
  }> {
    const message = await openpgp.readMessage({
      armoredMessage: encryptedText,
    });

    const decryptedPrivateKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: privateKey }),
      passphrase: passphrase || '',
    });

    const decryptOptions: openpgp.DecryptOptions = {
      message,
      decryptionKeys: decryptedPrivateKey,
      format: 'utf8',
    };

    // Add verification if public key provided
    if (verifyingPublicKey) {
      decryptOptions.verificationKeys = await openpgp.readKey({ 
        armoredKey: verifyingPublicKey 
      });
    }

    const { data, signatures } = await openpgp.decrypt(decryptOptions);
    
    return {
      data: data as string,
      signatures: signatures as openpgp.VerificationResult[],
    };
  }

  /**
   * Encrypt binary data (attachments)
   */
  static async encryptBinary(
    data: Uint8Array,
    recipientPublicKeys: string[],
    filename?: string
  ): Promise<string> {
    const publicKeys = await Promise.all(
      recipientPublicKeys.map(key => openpgp.readKey({ armoredKey: key }))
    );

    const message = await openpgp.createMessage({
      binary: data,
      filename,
      format: 'binary',
    });

    const encrypted = await openpgp.encrypt({
      message,
      encryptionKeys: publicKeys,
      format: 'armored',
    });

    return encrypted as string;
  }

  /**
   * Decrypt binary data
   */
  static async decryptBinary(
    encryptedData: string,
    privateKey: string,
    passphrase?: string
  ): Promise<Uint8Array> {
    const message = await openpgp.readMessage({
      armoredMessage: encryptedData,
    });

    const decryptedPrivateKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: privateKey }),
      passphrase: passphrase || '',
    });

    const { data } = await openpgp.decrypt({
      message,
      decryptionKeys: decryptedPrivateKey,
      format: 'binary',
    });

    return data as Uint8Array;
  }

  /**
   * Sign a message
   */
  static async sign(
    text: string,
    privateKey: string,
    passphrase?: string
  ): Promise<string> {
    const decryptedPrivateKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: privateKey }),
      passphrase: passphrase || '',
    });

    const message = await openpgp.createCleartextMessage({ text });
    
    const signed = await openpgp.sign({
      message,
      signingKeys: decryptedPrivateKey,
      format: 'armored',
    });

    return signed as string;
  }

  /**
   * Verify a signed message
   */
  static async verify(
    signedMessage: string,
    publicKey: string
  ): Promise<{
    data: string;
    verified: boolean;
  }> {
    const message = await openpgp.readCleartextMessage({
      cleartextMessage: signedMessage,
    });

    const verificationKey = await openpgp.readKey({ armoredKey: publicKey });

    const verificationResult = await openpgp.verify({
      message,
      verificationKeys: verificationKey,
    });

    const { data, signatures } = verificationResult;
    const verified = signatures.length > 0 && 
                    await signatures[0].verified;

    return {
      data: data as string,
      verified,
    };
  }

  /**
   * Export public key in various formats
   */
  static async exportPublicKey(
    publicKey: string,
    format: 'armored' | 'binary' = 'armored'
  ): Promise<string | Uint8Array> {
    const key = await openpgp.readKey({ armoredKey: publicKey });
    
    if (format === 'binary') {
      return key.write();
    }
    
    return key.armor();
  }

  /**
   * Get key information
   */
  static async getKeyInfo(publicKey: string): Promise<{
    fingerprint: string;
    keyId: string;
    userIds: string[];
    created: Date;
    expires?: Date;
    algorithm: string;
  }> {
    const key = await openpgp.readKey({ armoredKey: publicKey });
    
    return {
      fingerprint: key.getFingerprint(),
      keyId: key.getKeyID().toHex(),
      userIds: key.getUserIDs(),
      created: key.getCreationTime(),
      expires: await key.getExpirationTime(),
      algorithm: key.getAlgorithmInfo().algorithm,
    };
  }
}