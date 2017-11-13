package isp.signatures;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.spec.KeySpec;

public class KeyDerivation {
    public static void main(String[] args) throws Exception {
        // password from which the key will be derived
        final String password = "my password";

        // supposed to be random
        final byte[] salt = "89fjh3409fdj390fk".getBytes("UTF-8");

        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        // provide the password, salt, number of iterations and the number of required bits
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt, 10000, 128);
        final SecretKey key = pbkdf.generateSecret(specs);

        System.out.printf("key = %s%n", DatatypeConverter.printHexBinary(key.getEncoded()));
        System.out.printf("len(key) = %d bytes", key.getEncoded().length);
    }
}
