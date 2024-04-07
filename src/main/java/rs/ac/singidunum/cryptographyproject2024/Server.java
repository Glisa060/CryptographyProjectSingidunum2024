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
public class Server {

    private static SecretKey aesKey;

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server started. Waiting for client...");

        // Diffie-Hellman Key Exchange
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());

        while (true) {
            Socket socket = serverSocket.accept();
            System.out.println("Client connected.");

            // Send public key to client
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.writeObject(keyPair.getPublic());
            out.flush();

            // Receive client's public key
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            PublicKey clientPublicKey = (PublicKey) in.readObject();

            // Generate shared secret
            keyAgreement.doPhase(clientPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // Derive AES key from shared secret
            aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

            // Start a new thread to handle client
            new Thread(new ClientHandler(socket)).start();
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

                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
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
}
