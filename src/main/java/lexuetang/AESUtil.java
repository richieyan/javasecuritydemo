package lexuetang;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * User: richie.yan
 * Date: 5/31/13
 * Time: 10:16 PM
 */
public class AESUtil {

    public static byte[] decrypt(byte[] data, byte[] keyBytes, byte[] ivBtyes) throws Exception{
        Cipher cipher = getCipher();
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBtyes);
        cipher.init(Cipher.DECRYPT_MODE,key,iv);
        return cipher.doFinal(data);
    }

    public static byte[] encrypt(byte[] data, byte[] keyBytes, byte[] ivBtyes) throws Exception{
        Cipher cipher = getCipher();
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBtyes);
        cipher.init(Cipher.ENCRYPT_MODE,key,iv);
        return cipher.doFinal(data);
    }

    private static int KEY_SIZE = 128;

    public static byte[] generateKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE, new SecureRandom());
        SecretKey key = generator.generateKey();
        return key.getEncoded();
    }

    private static String AES_CTR_NoPadding = "AES/CTR/NoPadding";

    public static Cipher getCipher() {
        try {
            Cipher cipher = Cipher.getInstance(AES_CTR_NoPadding);
            return cipher;
        }catch (Exception e){
            throw new RuntimeException("cannot get cipher by " + AES_CTR_NoPadding);
        }
    }

}


