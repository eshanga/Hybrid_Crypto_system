import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class ClientAlice {

    public static void main(String[] args) throws Exception {
        // Connect to server
        Socket socket = new Socket("localhost", 8080);
        System.out.println("Connected to server.");

        // Streams for communication
        DataInputStream input = new DataInputStream(socket.getInputStream());
        DataOutputStream output = new DataOutputStream(socket.getOutputStream());

        // Generate Alice's RSA key pair
        KeyPair keyPairAlice = generateKeyPair();
        System.out.println("Alice's RSA key pair generated.");

        // Send Alice's public key to server (Bob)
        String alicePublicKey = Base64.getEncoder().encodeToString(keyPairAlice.getPublic().getEncoded());
        output.writeUTF(alicePublicKey);
        System.out.println("Alice's public key sent to server.");

        // Receive encrypted symmetric key from server
        String encryptedSymmetricKey = input.readUTF();
        System.out.println("Encrypted symmetric key received.");

        // Decrypt symmetric key using Alice's private key
        SecretKey symmetricKey = decryptSymmetricKey(keyPairAlice.getPrivate(), encryptedSymmetricKey);
        System.out.println("Symmetric key decrypted.");

        // Encrypt message using decrypted symmetric key
        String message = "Hello Double Check Authentication Message";
        System.out.println("Message at Alice: " + message);

        String encryptedMessage = encryptMessage(symmetricKey, message);
        output.writeUTF(encryptedMessage);
        System.out.println("Encrypted message sent to server.");

        // Receive and decrypt server's response
        String encryptedResponse = input.readUTF();
        String decryptedResponse = decryptMessage(symmetricKey, encryptedResponse);
        System.out.println("Decrypted response from server: " + decryptedResponse);

        // Close connections
        input.close();
        output.close();
        socket.close();
    }

    // Method to generate RSA key pair
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    // Decrypt symmetric key with RSA private key
    public static SecretKey decryptSymmetricKey(PrivateKey privateKey, String encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
        byte[] decryptedKey = cipher.doFinal(decodedKey);
        return new SecretKeySpec(decryptedKey, "AES");
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
