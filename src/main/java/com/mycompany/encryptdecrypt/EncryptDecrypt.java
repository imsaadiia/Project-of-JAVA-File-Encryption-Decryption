package com.mycompany.encryptdecrypt;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EncryptDecrypt {

    // Method to generate a symmetric key for AES, DES, or Blowfish
    public static SecretKey generateKey(String algorithm, int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm); // Key generator instance
        keyGen.init(keySize); // Initialize with the given key size
        return keyGen.generateKey(); // Generate the key
    }

    // Method to generate an RSA key pair
    public static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA"); // Key pair generator instance
        keyPairGen.initialize(keySize); // Initialize with the given key size
        return keyPairGen.generateKeyPair(); // Generate the key pair
    }

    // Method to encrypt data using a symmetric key
    public static byte[] encrypt(byte[] data, SecretKey key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm); // Cipher instance for the given algorithm
        cipher.init(Cipher.ENCRYPT_MODE, key); // Initialize cipher in encrypt mode
        return cipher.doFinal(data); // Perform encryption
    }

    // Method to encrypt data using an RSA public key
    public static byte[] encryptRSA(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA"); // Cipher instance for RSA
        cipher.init(Cipher.ENCRYPT_MODE, key); // Initialize cipher in encrypt mode
        return cipher.doFinal(data); // Perform encryption
    }

    // Method to decrypt data using a symmetric key
    public static byte[] decrypt(byte[] encryptedData, SecretKey key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm); // Cipher instance for the given algorithm
        cipher.init(Cipher.DECRYPT_MODE, key); // Initialize cipher in decrypt mode
        return cipher.doFinal(encryptedData); // Perform decryption
    }

    // Method to decrypt data using an RSA private key
    public static byte[] decryptRSA(byte[] encryptedData, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA"); // Cipher instance for RSA
        cipher.init(Cipher.DECRYPT_MODE, key); // Initialize cipher in decrypt mode
        return cipher.doFinal(encryptedData); // Perform decryption
    }

    // Method to save a symmetric key to a file
    public static void saveKey(SecretKey key, String fileName) throws Exception {
        byte[] keyBytes = key.getEncoded(); // Get encoded key bytes
        String encodedKey = Base64.getEncoder().encodeToString(keyBytes); // Encode key as a Base64 string
        Files.write(Paths.get(fileName), encodedKey.getBytes()); // Write the key to the file
    }

    // Method to save an RSA key to a file
    public static void saveKey(byte[] keyBytes, String fileName) throws Exception {
        String encodedKey = Base64.getEncoder().encodeToString(keyBytes); // Encode key as a Base64 string
        Files.write(Paths.get(fileName), encodedKey.getBytes()); // Write the key to the file
    }

    // Method to load a symmetric key from a file
    public static SecretKey loadKey(String algorithm, String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName)); // Read key bytes from the file
        String encodedKey = new String(keyBytes); // Convert bytes to string
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey); // Decode Base64 string
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, algorithm); // Create a new SecretKeySpec
    }

    // Method to load an RSA key from a file
    public static byte[] loadRSAKey(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName)); // Read key bytes from the file
        String encodedKey = new String(keyBytes); // Convert bytes to string
        return Base64.getDecoder().decode(encodedKey); // Decode Base64 string
    }

    // Method to load an RSA public key from a file
    public static PublicKey loadRSAPublicKey(String fileName) throws Exception {
        byte[] keyBytes = loadRSAKey(fileName); // Load key bytes from the file
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes); // Create a key spec
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Key factory instance
        return keyFactory.generatePublic(spec); // Generate public key
    }

    // Method to load an RSA private key from a file
    public static PrivateKey loadRSAPrivateKey(String fileName) throws Exception {
        byte[] keyBytes = loadRSAKey(fileName); // Load key bytes from the file
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes); // Create a key spec
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Key factory instance
        return keyFactory.generatePrivate(spec); // Generate private key
    }

    // Main method
    public static void main(String[] args) {
        // File paths
        String originalFile = "originalFile.txt"; // Original file name
        String aesEncryptedFile = "aesEncryptedFile.enc"; // AES encrypted file name
        String desEncryptedFile = "desEncryptedFile.enc"; // DES encrypted file name
        String blowfishEncryptedFile = "blowfishEncryptedFile.enc"; // Blowfish encrypted file name
        String rsaEncryptedFile = "rsaEncryptedFile.enc"; // RSA encrypted file name
        String aesDecryptedFile = "aesDecryptedFile.txt"; // AES decrypted file name
        String desDecryptedFile = "desDecryptedFile.txt"; // DES decrypted file name
        String blowfishDecryptedFile = "blowfishDecryptedFile.txt"; // Blowfish decrypted file name
        String rsaDecryptedFile = "rsaDecryptedFile.txt"; // RSA decrypted file name
        String aesKeyFile = "aesSecretKey.key"; // AES key file name
        String desKeyFile = "desSecretKey.key"; // DES key file name
        String blowfishKeyFile = "blowfishSecretKey.key"; // Blowfish key file name
        String rsaPublicKeyFile = "rsaPublicKey.key"; // RSA public key file name
        String rsaPrivateKeyFile = "rsaPrivateKey.key"; // RSA private key file name

        try {
            // Generate and save AES key
            SecretKey aesKey = generateKey("AES", 128); // Generate AES key
            saveKey(aesKey, aesKeyFile); // Save AES key

            // Generate and save DES key
            SecretKey desKey = generateKey("DES", 56); // Generate DES key
            saveKey(desKey, desKeyFile); // Save DES key

            // Generate and save Blowfish key
            SecretKey blowfishKey = generateKey("Blowfish", 128); // Generate Blowfish key
            saveKey(blowfishKey, blowfishKeyFile); // Save Blowfish key

            // Generate and save RSA key pair
            KeyPair rsaKeyPair = generateRSAKeyPair(2048); // Generate RSA key pair
            saveKey(rsaKeyPair.getPublic().getEncoded(), rsaPublicKeyFile); // Save RSA public key
            saveKey(rsaKeyPair.getPrivate().getEncoded(), rsaPrivateKeyFile); // Save RSA private key

            // Read file data
            byte[] fileData = Files.readAllBytes(Paths.get(originalFile)); // Read original file data

            // Encrypt and decrypt using AES
            byte[] aesEncryptedData = encrypt(fileData, aesKey, "AES"); // Encrypt data using AES
            Files.write(Paths.get(aesEncryptedFile), aesEncryptedData); // Write AES encrypted data to file
            SecretKey loadedAesKey = loadKey("AES", aesKeyFile); // Load AES key from file
            byte[] aesDecryptedData = decrypt(aesEncryptedData, loadedAesKey, "AES"); // Decrypt data using AES
            Files.write(Paths.get(aesDecryptedFile), aesDecryptedData); // Write AES decrypted data to file

            // Encrypt and decrypt using DES
            byte[] desEncryptedData = encrypt(fileData, desKey, "DES"); // Encrypt data using DES
            Files.write(Paths.get(desEncryptedFile), desEncryptedData); // Write DES encrypted data to file
            SecretKey loadedDesKey = loadKey("DES", desKeyFile); // Load DES key from file
            byte[] desDecryptedData = decrypt(desEncryptedData, loadedDesKey, "DES"); // Decrypt data using DES
            Files.write(Paths.get(desDecryptedFile), desDecryptedData); // Write DES decrypted data to file

            // Encrypt and decrypt using Blowfish
                        byte[] blowfishEncryptedData = encrypt(fileData, blowfishKey, "Blowfish"); // Encrypt data using Blowfish
            Files.write(Paths.get(blowfishEncryptedFile), blowfishEncryptedData); // Write Blowfish encrypted data to file
            SecretKey loadedBlowfishKey = loadKey("Blowfish", blowfishKeyFile); // Load Blowfish key from file
            byte[] blowfishDecryptedData = decrypt(blowfishEncryptedData, loadedBlowfishKey, "Blowfish"); // Decrypt data using Blowfish
            Files.write(Paths.get(blowfishDecryptedFile), blowfishDecryptedData); // Write Blowfish decrypted data to file

            // Encrypt and decrypt using RSA
            PublicKey rsaPublicKey = loadRSAPublicKey(rsaPublicKeyFile); // Load RSA public key from file
            PrivateKey rsaPrivateKey = loadRSAPrivateKey(rsaPrivateKeyFile); // Load RSA private key from file
            byte[] rsaEncryptedData = encryptRSA(fileData, rsaPublicKey); // Encrypt data using RSA
            Files.write(Paths.get(rsaEncryptedFile), rsaEncryptedData); // Write RSA encrypted data to file
            byte[] rsaDecryptedData = decryptRSA(rsaEncryptedData, rsaPrivateKey); // Decrypt data using RSA
            Files.write(Paths.get(rsaDecryptedFile), rsaDecryptedData); // Write RSA decrypted data to file

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}


