import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Mac;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;


public class GSatMicroMessageToMobile {
    private final static String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private final static int CHAR_LIMIT = 226; // 255 byte firmware payload limit, 11 bytes for wrapping, 16 bytes for encryption (255-11-16)
    private final static int ASSUMED_VERSION = 6;
    private final static char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private final static boolean DEBUG = true;

    public static void main(String[] args) throws Exception
    {
	final String IMEI = "300534060302080";
	String customAuthKey = null;
	byte [] result;

	try {
	    result = wrapMessage(createPingMessage(), IMEI, customAuthKey);
	} catch (GeneralSecurityException e) {
	    e.printStackTrace();
	    return;
	}
	System.out.println("result.length = " + result.length);
	System.out.println(bytesToHex(result, 4));
    }

    private static void debug(String msg)
    {
	if (DEBUG)
	    System.out.println(msg);
    }

    /**
     *  Computes the PBKDF2 hash of a password.
     *
     * @param   password    the password to hash.
     * @param   salt        the salt
     * @param   iterations  the iteration count (slowness factor)
     * @param   bytes       the length of the hash to compute in bytes
     * @return              the PBDKF2 hash of the password
     */
    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
	    throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
	SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
	return skf.generateSecret(spec).getEncoded();
    }

    private static List<Byte> createPingMessage()
    {
	List<Byte> wrappedPingMsg = new ArrayList<Byte>();

	wrappedPingMsg.add((byte)9); //messageType "ping message"
	wrappedPingMsg.add((byte)0); //message "Ping = 0x0, Pong = 0x1"

	return wrappedPingMsg;
    }

    /** Generates a default authorization key. */
    public static byte[] getDefaultAuthKey(String imei)
	    throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	final byte[] SALT = hexStringToByteArray(
		"549ac18830c8ac9208d05b41813b0d6149a21d459ae0ad12eccda3d492b981e2");

	debug("SALT            = " + bytesToHex(SALT, 4));
	debug("imei            = " + imei);
	byte[] authKey = pbkdf2(imei.toCharArray(), SALT, 1000, 20);
	debug("authKey         = " + bytesToHex(authKey, 4));
	return authKey;
    }

    /**
     * Wrap and sign a request message.
     * @param	requestMsg	the message
     * @param	authKeyBase64	a base64 encoded authorization key
     * @return			The wrapped message bytes
     */
    public static byte[] wrapMessage(List<Byte> requestMsg, String imei, String authKeyBase64)
	    throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException
    {
	byte[] wrappedByteArray = null;
	byte[] authKey;

	// version 2+
	List<Byte> wrapped = new ArrayList<Byte>();

	wrapped.add((byte) 0); // add message header
	wrapped.addAll(requestMsg); // add payload

	// Convert request List<Byte> to byte[] array
	Byte[] requestBytes	= requestMsg.toArray(new Byte[requestMsg.size()]);
	byte[] requestByteArray	= ArrayUtils.toPrimitive(requestBytes);
	debug("requestByteArray= " + bytesToHex(requestByteArray, 4));
	if (authKeyBase64 != null) {
	    debug("authKeyBase64   = " + authKeyBase64);
	    authKey = Base64.decodeBase64(authKeyBase64);
	} else {
	    authKey = getDefaultAuthKey(imei);
	}

	// Hash request
	SecretKeySpec secret_key = new SecretKeySpec(authKey, "HmacSHA256");
	Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
	sha256_HMAC.init(secret_key);
	byte [] request_hash = sha256_HMAC.doFinal(requestByteArray);
	debug("secret_key      = " + bytesToHex(secret_key.getEncoded(), 4));
	debug("request_hash    = " + bytesToHex(request_hash, 4));

	// Convert to hmac-sha256-80
	byte [] hash80_request = new byte[10];
	System.arraycopy(request_hash, 0, hash80_request, 0, hash80_request.length);
	debug("hash80_request  = " + bytesToHex(hash80_request, 4));

	// Add hashed hmac
	wrapped.addAll(Arrays.asList(ArrayUtils.toObject(hash80_request)));

	// Convert List<Byte> to byte[] array
	Byte[] wrappedBytes = wrapped.toArray(new Byte[wrapped.size()]);
	wrappedByteArray =ArrayUtils.toPrimitive(wrappedBytes);
	debug("wrappedByteArray= " + bytesToHex(wrappedByteArray, 4));
	debug("DeviceHmac      = " + bytesToHex(hexStringToByteArray("AFA7AE49C2D642E1C38C"), 4));

	return wrappedByteArray;
    }

    public static byte[] wrapMessage(List<Byte> requestMsg, String imei)
	    throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException
    {
	return wrapMessage(requestMsg, imei, null);
    }

    public static byte[] hexStringToByteArray(String s)
    {
	int len = s.length();
	byte[] data = new byte[len / 2];
	for (int i = 0; i < len; i += 2) {
	    data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
			  + Character.digit(s.charAt(i+1), 16));
	}
	return data;
    }

    public static String bytesToHex(byte[] bytes, int group)
    {
	int spaces = group > 0 ? bytes.length / group + 1 : 0;
	int s = 0;
	char[] hexChars = new char[bytes.length * 2 + spaces];
	for (int j = 0; j < bytes.length; j++ ) {
	    int v = bytes[j] & 0xFF;

	    if (j > 0 && j % group == 0) {
		hexChars[s++ + j * 2] = ' ';
	    }

	    hexChars[s + j * 2] = HEX_ARRAY[v >>> 4];
	    hexChars[s + j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	}
	return new String(hexChars);
    }
}
