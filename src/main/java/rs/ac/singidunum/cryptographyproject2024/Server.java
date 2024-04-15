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
 * @author Milan
 */
public class Server {

    private static SecretKey aesKey;

    public static void main(String[] args) throws Exception {
        // Generate RSA Key Pair for signing
        KeyPair rsaKeyPair = generateRSAKeyPair();
        // Store server's public key
        PublicKey rsaServerPublicKey = rsaKeyPair.getPublic(); // Store server's public key
        // Store server's private key
        PrivateKey rsaServerPrivateKey = rsaKeyPair.getPrivate(); // Store server's private key

        // Start the server socket
        try (ServerSocket serverSocket = new ServerSocket(12345)) {
            System.out.println("Server started. Waiting for client...");

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("Client connected.");

                // Diffie-Hellman Key Exchange
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
                keyPairGen.initialize(2048);
                KeyPair keyPair = keyPairGen.generateKeyPair();
                KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
                keyAgreement.init(keyPair.getPrivate());

                // Receive client's Diffie-Hellman public key and its signature
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                PublicKey rsaPublicKey = (PublicKey) in.readObject();
                PublicKey clientPublicKey = (PublicKey) in.readObject();
                byte[] clientPublicKeySignature = (byte[]) in.readObject();

                // Verify client's Diffie-Hellman public key signature
                boolean signatureVerified = verifySignature(clientPublicKey.getEncoded(), clientPublicKeySignature, rsaPublicKey);
                if (!signatureVerified) {
                    System.err.println("Client public key signature verification failed.");
                    throw new Exception("Client public key signature verification failed.");
                } else {
                    System.out.println("Client public key signature verified successfully.");
                }

                byte[] signedPublicKey = signData(keyPair.getPublic().getEncoded(), rsaServerPrivateKey);

                // Send signed public key to client
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(keyPair.getPublic());
                out.writeObject(rsaServerPublicKey);
                out.writeObject(signedPublicKey); // Send server's signed public key to client
                out.flush();

                // Generate shared secret
                keyAgreement.init(keyPair.getPrivate()); // Initialize with server's private key
                keyAgreement.doPhase(clientPublicKey, true);
                byte[] sharedSecret = keyAgreement.generateSecret();

                // Derive AES key from shared secret
                aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

                // Start a new thread to handle client
                new Thread(new ClientHandler(socket)).start();
            }
        }
    }

    static class ClientHandler implements Runnable {

        private final Socket socket;
        private final Cipher aesCipher;

        public ClientHandler(Socket socket) throws Exception {
            this.socket = socket;
            aesCipher = Cipher.getInstance("AES");
        }

        @Override
        public void run() {
            try {
                try (socket) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

                    String clientMessage;
                    while ((clientMessage = reader.readLine()) != null) {
                        System.out.println("Received encrypted message: " + clientMessage);
                        String decryptedMessage = decryptMessage(clientMessage);
                        System.out.println("Decrypted message: " + decryptedMessage);

                        // Respond to the client
                        String response = "Server received your message: " + decryptedMessage;
                        String encryptedResponse = encryptMessage(response);
                        writer.println(encryptedResponse);
                        writer.flush();
                    }
                }
            } catch (Exception ignored) {
            }
        }

        private String decryptMessage(String encryptedMessage) throws Exception {
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = aesCipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        }

        private String encryptMessage(String message) throws Exception {
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedBytes = aesCipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    private static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}