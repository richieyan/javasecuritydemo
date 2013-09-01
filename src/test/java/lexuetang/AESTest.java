package lexuetang;

import java.security.*;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKKeyFactory;
import org.junit.Before;
import org.junit.Test;

public class AESTest {

    private static String AES_CTR_NoPadding = "AES/CTR/NoPadding";

	@Before
	public void setupProvider(){
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		Provider[] providers = Security.getProviders();
		for (int i = 0; i < providers.length; i++) {
			System.out.println(providers[i].getName());
		}
	}

    @Test
    public void testGenerateKey() throws Exception{
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128, new SecureRandom());
        SecretKey key = generator.generateKey();
        System.out.println(Arrays.toString(key.getEncoded()));
        System.out.println("KeyLEN:"+(key.getEncoded().length * 8));
        String base64Key = Base64.encodeBase64String(key.getEncoded());
        System.out.println("Base64 KEY:"+base64Key);

    }
	@Test
	public void testGetCipher() throws Exception {
		long t = System.currentTimeMillis();

		Cipher cipher = Cipher.getInstance(AES_CTR_NoPadding);
		System.out.println("t:"+(System.currentTimeMillis() - t));
		System.out.println(cipher.getProvider().getName());
		
		t = System.currentTimeMillis();
		Cipher cipher2 = Cipher.getInstance(AES_CTR_NoPadding);
		System.out.println("t:"+(System.currentTimeMillis() - t));
		System.out.println(cipher2.getProvider().getName());
	}

	@Test
	public void testEncryptAndDecrypt() throws Exception {

        String message = "this is a plain text. 这是一段文本。";
//        byte[] key = AESUtil.generateKey();
        byte[] key = {-81, -6, -54, -4, 27, 96, 72, -99, -28, -11, -8, 78, 116, 101, -6, -4};
        byte[] iv = key;//use key as iv


        System.out.println("key:" + Arrays.toString(key));

        //长度测试（可以支持任意长度）
//        StringBuilder sb = new StringBuilder();
//        for (int i = 0; i < 3173; i++) {
//            char a  = (char) ('A' + i % 26);
//            sb.append(a);
//        }
//
//        message = sb.toString();
//        System.out.println(sb.toString());

        //加密
        byte[] data = message.getBytes();
        byte[] result = AESUtil.encrypt(data,key,iv);
        System.out.println("LEN:"+result.length);
        System.out.println(Arrays.toString(result));

        //解密
        result = AESUtil.decrypt(result,key, iv);
        System.out.println(new String(result));
    }

    @Test
    public void testDecrypt() throws Exception
    {
        byte[] data = {-96,124,-1,60,-81,-108,-65,3,-29,-66,31,78,80,-53,-47,-22,118,-89,-82,82,-104,6,7,123,-29,1,-92,-70,-113,91,-115,64,42,84,-75,112,-105,-13,41,1,116,4,113,77,80,-100,81,115};
        byte[] key = {71,-67,-38,24,-62,30,-60,-51,46,-109,-7,-110,41,36,-83,-115};
        byte[] iv = key;
        byte[] result = AESUtil.decrypt(data,key,iv);
        System.out.println(new String(result));

    }
}
