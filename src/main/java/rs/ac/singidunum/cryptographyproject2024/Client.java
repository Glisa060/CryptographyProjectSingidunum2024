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
        Socket socket = new Socket("localhost", 12345);
        System.out.println("Connected to server.");

        // Diffie-Hellman Key Exchange
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());

        // Send public key to server
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        out.writeObject(keyPair.getPublic());
        out.flush();

        // Receive server's public key
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        PublicKey serverPublicKey = (PublicKey) in.readObject();

        // Generate shared secret
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Derive AES key from shared secret
        aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

        // Start thread to handle user input and sending messages
        new Thread(new ClientHandler(socket)).start();
    }

    static class ClientHandler implements Runnable {

        private final Socket socket;
        private final Cipher aesCipher;

        public ClientHandler(Socket socket) throws Exception {
            this.socket = socket;
            aesCipher = Cipher.getInstance("AES");
        }

        private String calculateHash(String message) throws NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(message.getBytes());
            return Base64.getEncoder().encodeToString(hashBytes);
        }

        private String decryptMessage(String encryptedMessage) throws Exception {
            Cipher aesCipher2 = Cipher.getInstance("AES");
            aesCipher2.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = aesCipher2.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        }

        private String encryptMessage(String message) throws Exception {
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedBytes = aesCipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }

        @Override
        public void run() {
            try {
                BufferedReader userInputReader = new BufferedReader(new InputStreamReader(System.in));
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
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
            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    // Close the socket gracefully
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }
}
