
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSA {
    public static void main(String[] unused) throws Exception {
        // Generate key pair
        String cryptSpec = "RSA"; //using RSA

        //Key Pair Generator for Sender
        KeyPairGenerator SenderKPG = KeyPairGenerator.getInstance("RSA");
        SenderKPG.initialize(2048);
        KeyPair SenderKeyPair = SenderKPG.generateKeyPair();

        //Key Pair Generator for Receiver
        KeyPairGenerator ReceiverKPG = KeyPairGenerator.getInstance("RSA");
        SenderKPG.initialize(2048);
        KeyPair ReceiverKeyPair = ReceiverKPG.generateKeyPair();

        //Signature w/Secure Random
        Signature signature =Signature.getInstance("SHA256withRSA");
        SecureRandom secureRandom =new SecureRandom();
        secureRandom.setSeed(10);
        signature.initSign(SenderKeyPair.getPrivate(), secureRandom);

        //Sender
        PublicKey ReceiverPK= ReceiverKeyPair.getPublic();
        PublicKey SenderPRK= SenderKeyPair.getPublic();

        byte[] m = "Hello world".getBytes();

        //Encryption Box
        Cipher SenderEncryptionBox = Cipher.getInstance(cryptSpec);
        SenderEncryptionBox.init(Cipher.ENCRYPT_MODE, ReceiverPK);
        byte[] c = SenderEncryptionBox.doFinal(m);

        signature.update(c);
        byte[] sig =signature.sign();

        String cipher = Base64.getEncoder().encodeToString(c);
        System.out.println("Ciphertext: " + cipher);

        //Receiver
        c = Base64.getDecoder().decode(cipher);
        PrivateKey ReceiverPRK = ReceiverKeyPair.getPrivate();
        PublicKey SenderPK = SenderKeyPair.getPublic();

        Cipher RecieverDecryptionBox = Cipher.getInstance(cryptSpec);
        RecieverDecryptionBox.init(Cipher.DECRYPT_MODE, ReceiverPRK);

        //Signature
        Signature signature1 = Signature.getInstance("SHA256withRSA");
        signature1.initVerify(SenderKeyPair.getPublic());
        signature1.update(c);
        boolean authenticate =signature1.verify(sig);

        //auth check
        if (authenticate == false){
            System.out.println("Signature is fake");
            System.exit(1);
        }

        m=RecieverDecryptionBox.doFinal(c);

        //converting bytes to string -- so that it can be printed
        String s = new String(m);
        System.out.println(s);
    }
}