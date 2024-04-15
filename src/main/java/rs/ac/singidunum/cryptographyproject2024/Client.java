/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package rs.ac.singidunum.cryptographyproject2024;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

/**
 *
 * @author Milan
 */
public class Client {

    private static SecretKey aesKey;

    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket("localhost", 12345)) {
            System.out.println("Connected to server.");
            // Diffie-Hellman Key Exchange
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());

            // Generate RSA Key Pair for signing
            KeyPair rsaKeyPair = generateRSAKeyPair();

            // Sign the Diffie-Hellman public key with RSA private key
            byte[] signedPublicKey = signData(keyPair.getPublic().getEncoded(), rsaKeyPair.getPrivate());

            // Send signed public key to server
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.writeObject(keyPair.getPublic());
            out.writeObject(signedPublicKey);
            out.flush();
            
            // Receive server's public key and its signature
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            PublicKey serverPublicKey = (PublicKey) in.readObject();
            byte[] serverPublicKeySignature = (byte[]) in.readObject(); // Added line to read the signature

            // Verify server's public key signature
            System.out.println("Verifying server public key signature...");
            // Verify server's public key signature
            boolean signatureVerified = verifySignature(serverPublicKey.getEncoded(), serverPublicKeySignature, rsaKeyPair.getPublic());

            if (!signatureVerified) {
                System.err.println("Server public key signature verification failed.");
                throw new Exception("Server public key signature verification failed.");
            } else {
                System.out.println("Server public key signature verified successfully.");
            }

            // Generate shared secret
            keyAgreement.doPhase(serverPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // Derive AES key from shared secret
            aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

            // Create BufferedReader for reading messages from server
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            // Start reading user input and sending messages
            BufferedReader userInputReader = new BufferedReader(new InputStreamReader(System.in));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
            String userInput;
            while (true) {
                // Prompt the user to enter a message
                System.out.print("Enter message: ");
                userInput = userInputReader.readLine();

                // Encrypt user input before sending
                String encryptedMessage = encryptMessage(userInput);
                writer.println(encryptedMessage);
                writer.flush();

                // Receive encrypted message from the server
                String encryptedResponse = reader.readLine();
                if (encryptedResponse == null) {
                    // If server closed the connection, break the loop
                    break;
                }
                System.out.println("Received encrypted message from server: " + encryptedResponse);

                // Decrypt the message from the server
                String decryptedResponse = decryptMessage(encryptedResponse);
                System.out.println("Decrypted message from server: " + decryptedResponse);

                // Calculate hash of decrypted message from server
                String hash = calculateHash(decryptedResponse);
                System.out.println("Hash of decrypted message from server: " + hash);
            }
            // Close resources
        }
    }

    private static String calculateHash(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    private static String decryptMessage(String encryptedMessage) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = aesCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    private static String encryptMessage(String message) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedBytes = aesCipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    private static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}
