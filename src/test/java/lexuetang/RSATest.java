package lexuetang;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

public class RSATest {




    //PKCS#8 1024bit的密钥长度，采用PKCS#1padding的明文大小在117字节(128 – 11)
    //如果使用NoPadding的方式，明文大小可以是128字节
	String PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMiXPgk4sKssKnH3\n" +
            "nGDIESMflC9Z95IquKeuyN/PdJ3G7qo/vrgBi0qV1fifE89REK2jdcvt+Q4i+S2W\n" +
            "7E3Eg3DoUYB3KqgvUHRhV9ZJs3x5EWeK8F4k2paIGbHJXbYi+Zbi46TwwVNeftKe\n" +
            "+m0QsCPR3423fYTFlBgUjZnehJKnAgMBAAECgYBCiYCneGmJ7hWKRlNV+ydMGk6C\n" +
            "QnqPvqIP5Td2ng8VwwYp7Qkraj+1FuyqEsJ0c3Rv1JffdGm32bwD9lseFMBwXbOq\n" +
            "O+WQ2cN1rEoI4uHdl72mIVLY9i3L5vgE+GSWyTPzXbP9F1QU2NQMI48I4aOAmNOT\n" +
            "XR2Cl4a2+2nb7rEzqQJBAPOypVXVloASI2PTZKr4gUPd6Y8v4LrraKahN96Becn5\n" +
            "1oMpXIBtDUt1W1+d+xKFZ1YF6A7TYxV241dd1pM6UhMCQQDSt4QNI4Gu0NpHWFEb\n" +
            "dyhEh96DHjxfz0nmFnb38t4DEnf9kee94mWlpnn+968dT2R0K48ojd9aWGj86KSi\n" +
            "bm+dAkEArvVD5DLawQnEpKeg72pIC7xnMSiTdD8MPA0kujdEg7A9xJ7OTVl9oP4Z\n" +
            "YrVeCvcBsG2/I925ljBrmU7CfaLyRwJAdEg9oRqFCDnNGy4LpEJ/gEIScv0OiDjW\n" +
            "KRkgkff+uGdKvC32Wv1C5sUV8bQxeNVFNC6Nk+2m4i6D0X14zQJwqQJBAMCzeONi\n" +
            "rEqXOp/51BkR4TFFEegtUlnv/LeQNfcO5ac9MKShFy1RF2YGkqJFmPwIw/NEbG/7\n" +
            "Kc6eRSVUTgwlN9Y=";


	String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIlz4JOLCrLCpx95xgyBEjH5Qv\n" +
            "WfeSKrinrsjfz3Sdxu6qP764AYtKldX4nxPPURCto3XL7fkOIvktluxNxINw6FGA\n" +
            "dyqoL1B0YVfWSbN8eRFnivBeJNqWiBmxyV22IvmW4uOk8MFTXn7SnvptELAj0d+N\n" +
            "t32ExZQYFI2Z3oSSpwIDAQAB";
	
	public static String RSA_ECB_PCKS1Padding = "RSA/ECB/PKCS1Padding";

	@Before
	public void setupProvider(){
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		Provider[] providers = Security.getProviders();
		for (int i = 0; i < providers.length; i++) {
			System.out.println(providers[i].getName());
		}
		
	}
	
	@Test
	public void testGetCipher() throws Exception {
		long t = System.currentTimeMillis();
		Cipher cipher = Cipher.getInstance(RSA_ECB_PCKS1Padding);
		System.out.println("t:"+(System.currentTimeMillis() - t));
		System.out.println(cipher.getProvider().getName());
		
		t = System.currentTimeMillis();
		Cipher cipher2 = Cipher.getInstance(RSA_ECB_PCKS1Padding);
		System.out.println("t:"+(System.currentTimeMillis() - t));
		System.out.println(cipher2.getProvider().getName());
	}

	@Test
	public void testReadPrivateKey() throws Exception {
		PrivateKey key = RSAUtil.getPrivateKey(PRIVATE_KEY);
        System.out.println(key);
    }
	
	@Test
	public void testReadPublicKey() throws Exception {
        PublicKey publicKey = RSAUtil.getPublicKey(PUBLIC_KEY);
        RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
        BigInteger modulus = rsaPublicKey.getModulus();
        BigInteger publicExponent = rsaPublicKey.getPublicExponent();
        System.out.println("m = " + modulus.toString(16));
        System.out.println("e = " + publicExponent.toString(16));
	}
	
	@Test
	public void testEncryptAndDecrypt() throws Exception {
		//使用公钥加密
        PublicKey publicKey = RSAUtil.getPublicKey(PUBLIC_KEY);
        String message = "RSA: this is a plain text. 这是一段文本。";

        //长度测试
//        StringBuilder sb = new StringBuilder();
//        for (int i = 0; i < 118; i++) {
//            char a  = (char) ('A' + i % 26);
//            sb.append(a);
//        }
//
//        message = sb.toString();
//        System.out.println(sb.toString());

        byte[] result = RSAUtil.encrypt(message.getBytes(),publicKey);
        System.out.println("LEN:"+result.length);
        //注意：每次的加密的结果相同
        System.out.println(Arrays.toString(result));

        //使用私钥解密
        PrivateKey privateKey = RSAUtil.getPrivateKey(PRIVATE_KEY);
        result = RSAUtil.decrypt(result,privateKey);
        System.out.println(new String(result));
    }


    @Test
    public void testDecrypt() throws Exception
    {
//        byte[] data = {-57,65,-64,46,-127,-68,-69,4,55,-121,91,-14,-74,-125,40,22,-114,33,84,96,-101,-43,-65,-62,-34,-76,113,41,-81,-26,113,54,-27,-34,-104,-98,112,-114,70,34,59,-47,62,98,5,-14,97,-12,96,64,-90,29,87,61,-34,-78,126,-59,-113,-116,29,-2,-49,-122,37,40,-65,92,69,93,-106,-60,-65,-17,-104,-94,-54,-66,50,16,104,-52,17,31,22,21,82,-1,66,-40,72,86,57,54,-39,43,27,44,-96,46,-52,73,-21,-87,104,-55,-54,4,34,40,-48,9,-54,-72,-103,-53,-91,10,95,83,-34,121,-101,90,120,-121,-61,-62};
        byte[] data = {20,66,100,122,99,-85,41,11,-84,-117,119,-36,-89,43,-45,-117,-95,-128,14,13,-61,75,56,-49,56,-122,13,-57,-124,79,64,5,-94,-67,83,37,79,-84,4,-16,-122,41,125,61,0,63,33,37,51,127,118,-50,-120,56,82,-71,-98,53,-109,107,81,-7,-83,-94,14,-58,27,-61,13,-78,-72,80,20,-60,-57,84,-96,15,57,-72,62,15,43,-33,80,-3,37,-51,-86,107,-19,-115,-31,-114,91,34,56,85,1,-127,23,22,127,-27,31,-38,-106,-106,-77,-80,-109,-16,-122,92,-68,51,-66,75,92,-36,19,-84,104,106,62,-2,-47,77};
//        byte[] data = {53,94,36,97,-77,-98,-44,84,120,-65,114,96,112,50,-21,-56,74,5,-112,-26,93,-91,-20,73,-114,-31,-126,72,40,-109,114,-100,27,48,-13,-36,79,1,-108,78,19,-93,26,78,-78,49,-37,-40,126,-127,-61,-119,45,119,-4,-101,112,13,-11,107,-120,-125,126,66,26,17,71,48,-44,90,55,14,-30,-107,-86,58,-25,43,39,-58,-98,-61,39,46,-127,66,123,90,43,30,113,64,81,74,79,-38,92,-92,-64,-37,-120,-6,96,-33,95,-126,107,127,86,-110,-76,74,-60,45,66,-30,90,102,-86,-91,-99,-97,-75,68,-36,-98,-56,62};
        //使用私钥解密
        PrivateKey privateKey = RSAUtil.getPrivateKey(PRIVATE_KEY);
        data = RSAUtil.decrypt(data,privateKey);
        System.out.println(new String(data));
    }
}
