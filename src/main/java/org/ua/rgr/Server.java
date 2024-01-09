package org.ua.rgr;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;

public class Server {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(9999);
            System.out.println("Server started. Waiting for client...");


            while (true) {
                startHandShake(serverSocket);
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void startHandShake(ServerSocket serverSocket) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Socket socket = serverSocket.accept();
        System.out.println("Client connected.");

        // Get rand hello string from client
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        byte[] randomClientString = (byte[]) in.readObject();

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        SecureRandom random = new SecureRandom();
        byte[] serverRandomBytes = new byte[12];
        random.nextBytes(serverRandomBytes);
        // Send rand hello string from server
        out.writeObject(serverRandomBytes);
        out.flush();

        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        // Send public key to client
        out.writeObject(publicKey);
        out.flush();

        // Receive encrypted secret premaster from client
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] encryptedSecret = (byte[]) in.readObject();
        byte[] secret = cipher.doFinal(encryptedSecret);
        System.out.println("Received secret: " + new String(secret));

        // Create session key on server
        byte[] session = concatenateByteArrays(randomClientString, Arrays.copyOfRange(secret, 0, 8), serverRandomBytes);
        System.out.println(new String(session, "UTF-8"));

        SecretKey sessionKey = new SecretKeySpec(session, "AES");

        Cipher sessionEncryptCipher = Cipher.getInstance("AES");
        sessionEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        Cipher sessionDecryptCipher = Cipher.getInstance("AES");
        sessionDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey);

        String readyMessage = "Ready";
        // Send ready to client
        out.writeObject(sessionEncryptCipher.doFinal(readyMessage.getBytes()));
        out.flush();

        // Get ready from client
        byte[] readyClientString = (byte[]) in.readObject();

        if (new String(sessionDecryptCipher.doFinal(readyClientString), "UTF-8").equals("Ready")) {
            System.out.println("Received client ready signal");
            while (true) {
                try {
                    byte[] messageFromClient = (byte[]) in.readObject();
                    String message = new String(sessionDecryptCipher.doFinal(messageFromClient), "UTF-8");
                    System.out.println(message);
                    if (message.equals("Stop")) {
                        System.out.println("Connection closed");
                        break;
                    }
                }catch (Exception e){
                    //
                }
            }
        }

        socket.close();
        // Close resources
        in.close();
        out.close();
    }

    public static byte[] concatenateByteArrays(byte[] array1, byte[] array2, byte[] array3) {
        byte[] result = new byte[array1.length + array2.length + array3.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        System.arraycopy(array3, 0, result, array1.length + array2.length, array3.length);
        return result;
    }
}
