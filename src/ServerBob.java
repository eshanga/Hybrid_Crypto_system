import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.spec.X509EncodedKeySpec;


public class ServerBob {

    public static void main(String[] args) throws Exception {
        // Create server socket
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Server is listening on port 8080...");

        // Wait for connection from client
        Socket socket = serverSocket.accept();
        System.out.println("Client connected");

        // Streams for communication
        DataInputStream input = new DataInputStream(socket.getInputStream());
        DataOutputStream output = new DataOutputStream(socket.getOutputStream());

        // Generate Bob's RSA KeyPair
        KeyPair keyPairBob = generateKeyPair();
        System.out.println("Bob's RSA key pair generated.");

        // Receive Alice's public key from client
        String alicePublicKeyString = input.readUTF();
        byte[] alicePublicKeyBytes = Base64.getDecoder().decode(alicePublicKeyString);
        PublicKey alicePublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(alicePublicKeyBytes));
        System.out.println("Received Alice's public key.");

        // Bob generates AES symmetric key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES 128-bit key
        SecretKey symmetricKeyBob = keyGen.generateKey();
        System.out.println("Bob's symmetric key generated.");

        // Encrypt symmetric key with Alice's public key
        String encryptedSymmetricKey = encryptSymmetricKey(alicePublicKey, symmetricKeyBob);
        System.out.println("Symmetric key encrypted with Alice's public key.");

        // Send encrypted symmetric key to Alice
        output.writeUTF(encryptedSymmetricKey);
        System.out.println("Encrypted symmetric key sent to Alice.");

        // Receive encrypted message from Alice
        String encryptedMessage = input.readUTF();
        System.out.println("Encrypted message received from Alice.");

        // Decrypt message using Bob's symmetric key
        String decryptedMessage = decryptMessage(symmetricKeyBob, encryptedMessage);
        System.out.println("Decrypted message from Alice: " + decryptedMessage);

        // Encrypt response message
        String encryptedResponse = encryptMessage(symmetricKeyBob, decryptedMessage);
        output.writeUTF(encryptedResponse);
        System.out.println("Encrypted response sent to Alice.");

        // Close connections
        input.close();
        output.close();
        socket.close();
        serverSocket.close();
    }

    // Method to generate RSA key pair
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    // Encrypt symmetric key with RSA public key
    public static String encryptSymmetricKey(PublicKey publicKey, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    // Encrypt message using AES symmetric key
    public static String encryptMessage(SecretKey secretKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    // Decrypt message using AES symmetric key
    public static String decryptMessage(SecretKey secretKey, String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedMessage = cipher.doFinal(decodedMessage);
        return new String(decryptedMessage);
    }
}
