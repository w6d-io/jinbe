import CryptoJS from 'crypto-js'
import { env } from '../config/index.js'

/**
 * Encrypts passwords using AES encryption
 * Used for storing database credentials securely
 */
export function encryptPassword(password: string): string {
  return CryptoJS.AES.encrypt(password, env.ENCRYPTION_KEY).toString()
}

/**
 * Decrypts passwords encrypted with encryptPassword
 */
export function decryptPassword(encryptedPassword: string): string {
  const bytes = CryptoJS.AES.decrypt(encryptedPassword, env.ENCRYPTION_KEY)
  return bytes.toString(CryptoJS.enc.Utf8)
}
