import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class HybridCryptoSystem {

    // Generate RSA Key Pair for Asymmetric encryption
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    // Encrypt symmetric key using RSA public key
    public static String encryptSymmetricKey(PublicKey publicKey, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    // Decrypt symmetric key using RSA private key
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

    public static void main(String[] args) throws Exception {
        // Key Pair Generation
        KeyPair KeyPair_Alice = generateKeyPair();
        KeyPair KeyPair_Bob = generateKeyPair();

        System.out.println("Alice's Public Key: " + Base64.getEncoder().encodeToString(KeyPair_Alice.getPublic().getEncoded()));

        System.out.println("==============================================================================================");

        System.out.println("Bob's Public Key: " + Base64.getEncoder().encodeToString(KeyPair_Bob.getPublic().getEncoded()));

        System.out.println("==============================================================================================");

        // Bob generates symmetric key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES 128-bit key
        SecretKey BobSymmetricKey = keyGen.generateKey();

        System.out.println("Bob's Symmetric Key: " + Base64.getEncoder().encodeToString(BobSymmetricKey.getEncoded()));

        System.out.println("==============================================================================================");

        // Bob encrypts symmetric key with Alice's public key and sends it
        String encryptedSymmetricKey = encryptSymmetricKey(KeyPair_Alice.getPublic(), BobSymmetricKey);
        System.out.println("Encrypted Symmetric Key (Bob -> Alice): " + encryptedSymmetricKey);

        System.out.println("==============================================================================================");

        // Alice decrypts the symmetric key using its private key
        SecretKey decryptedSymmetricKey = decryptSymmetricKey(KeyPair_Alice.getPrivate(), encryptedSymmetricKey);
        System.out.println("Decrypted Symmetric Key (Alice): " + Base64.getEncoder().encodeToString(decryptedSymmetricKey.getEncoded()));

        System.out.println("==============================================================================================");

        // Alice sends an encrypted check_message to Bob
        String check_message= "Hello this is Double Check Authentication Message";
        System.out.println("Check Authentication Message(at Alice): " + check_message);

        System.out.println("==============================================================================================");

        String encryptedCheckMessage = encryptMessage(decryptedSymmetricKey, check_message);
        System.out.println("Encrypted check_message(Alice -> Bob): " + encryptedCheckMessage);

        System.out.println("==============================================================================================");

        // Bob decrypts the check_message and replies with the same message encrypted with the symmetric key
        String decyptedChechMessage = decryptMessage(BobSymmetricKey, encryptedCheckMessage);
        System.out.println("Decrypted check_message(Bob): " + decyptedChechMessage);

        System.out.println("==============================================================================================");

        String response = encryptMessage(BobSymmetricKey, decyptedChechMessage);
        System.out.println("Encrypted Response (Bob -> Alice): " + response);

        System.out.println("==============================================================================================");

        // Alice decrypts the response to verify Bob
        String decryptedResponse = decryptMessage(decryptedSymmetricKey, response);
        System.out.println("Decrypted Response (Alice): " + decryptedResponse);
        

        System.out.println("==============================================================================================");

        if (decryptedResponse.equals(check_message)) {
            System.out.println("=============Secure Connection Confirmed=============");
        } else {
            System.out.println("Secure Connection Failed");
        }
    }
}
