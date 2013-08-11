package lexuetang;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

public class RSATest {




    //PKCS#8
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
        String message = "this is a plain text. 这是一段文本。";
        byte[] result = RSAUtil.encrypt(message.getBytes(),publicKey);
        System.out.println("LEN:"+result.length);
        System.out.println(Arrays.toString(result));

        //使用私钥解密
        PrivateKey privateKey = RSAUtil.getPrivateKey(PRIVATE_KEY);
        result = RSAUtil.decrypt(result,privateKey);
        System.out.println(new String(result));
    }


    @Test
    public void testDecrypt() throws Exception
    {
        byte[] data = {-57,65,-64,46,-127,-68,-69,4,55,-121,91,-14,-74,-125,40,22,-114,33,84,96,-101,-43,-65,-62,-34,-76,113,41,-81,-26,113,54,-27,-34,-104,-98,112,-114,70,34,59,-47,62,98,5,-14,97,-12,96,64,-90,29,87,61,-34,-78,126,-59,-113,-116,29,-2,-49,-122,37,40,-65,92,69,93,-106,-60,-65,-17,-104,-94,-54,-66,50,16,104,-52,17,31,22,21,82,-1,66,-40,72,86,57,54,-39,43,27,44,-96,46,-52,73,-21,-87,104,-55,-54,4,34,40,-48,9,-54,-72,-103,-53,-91,10,95,83,-34,121,-101,90,120,-121,-61,-62};
        //使用私钥解密
        PrivateKey privateKey = RSAUtil.getPrivateKey(PRIVATE_KEY);
        data = RSAUtil.decrypt(data,privateKey);
        System.out.println(new String(data));
    }
}
