/**
 * May 29, 2014
 * 10:36:29 AM
 * version 1.0.0
 * @author Rakeb.Void
 */

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Properties;

public class ECPSingVerify {
	private static String message;
	private static String ecCurveName;
	private static String ecRemotePubKey;
	private static String ecSignData;
	private static String signALG;

	/******************** EC Sign-Verify START ********************/
	/**
	 * This methods generates ECKeyPair, shows public key and write private key
	 * into a file "privateKey.key"
	 * 
	 * @return {@link KeyPair}
	 * @throws Exception
	 */
	public KeyPair ecKeyPairGenerator(String curveName) throws Exception {
		KeyPair keyPair;
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
				"ECDSA", "BC");
		ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(
				curveName);
		keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
		keyPair = keyPairGenerator.generateKeyPair();
		java.security.PublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
		System.out.println("JAVA EC PublicKey: "
				+ Helper.toHex(ecPublicKey.getEncoded()));

		// write private key into a file
		FileOutputStream fileOutputStream = new FileOutputStream(
				"ECPrivateKey.key");
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(
				fileOutputStream);
		objectOutputStream.writeObject(keyPair.getPrivate());
		objectOutputStream.close();
		return keyPair;
	}

	/**
	 * This method sign message with its internally generated private key
	 * 
	 * @param keyPair
	 * @param message
	 * @throws Exception
	 */
	public void ecSign(KeyPair keyPair, String message) throws Exception {
		Signature signature = Signature.getInstance(signALG, "BC");
		try {
			signature.initSign(keyPair.getPrivate(), new SecureRandom());
		} catch (Exception e) {
			System.out.println("Caught Exception in Signature getInstance: "
					+ e.toString());
		}

		signature.update(Helper.toByte(message));

		byte[] sigBytes = signature.sign();
		System.out.println("EC Sign-data	: " + Helper.toHex(sigBytes));
	}

	/**
	 * This method verify a sign data
	 * 
	 * @param sign
	 * @param ecPublicKey
	 * @param message
	 * @return <code>true</code> if verified, <code>false</code> otherwise
	 * @throws Exception
	 */
	public boolean ecVerify(String sign, ECPublicKey ecPublicKey, String message)
			throws Exception {
		Signature signature = Signature.getInstance(signALG, "BC");
		signature.initVerify(ecPublicKey);
		signature.update(Helper.toByte(message));

		return signature.verify(Helper.toByte(sign));
	}

	/******************** EC Sign-Verify END ********************/

	/**
	 * Convert a byte array public key into java public key object
	 * @return
	 * @throws Exception
	 */
	public static ECPublicKey genEcPubKey() throws Exception {
		KeyFactory factory = KeyFactory.getInstance("ECDSA", "BC");
		java.security.PublicKey ecPublicKey = (ECPublicKey) factory
				.generatePublic(new X509EncodedKeySpec(Helper
						.toByte(ecRemotePubKey)));
		return (ECPublicKey) ecPublicKey;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Properties properties = new Properties();
		properties.load(ECPSingVerify.class.getClassLoader().getResourceAsStream(
				"config.properties"));
		message = properties.getProperty("message");
		ecRemotePubKey = properties.getProperty("ecRemotePubKey");
		ecCurveName = properties.getProperty("ecCurveName");
		signALG = properties.getProperty("signALG");
		ecSignData = properties.getProperty("ecSignData");

		ECPSingVerify appletTest = new ECPSingVerify();

		// EC KeyPair generation
		KeyPair ecKeyPair = null;
		try {
			ecKeyPair = appletTest.ecKeyPairGenerator(ecCurveName);
		} catch (Exception e) {
			System.out.println("Caught Exception in KeyPair generation: "
					+ e.toString());
		}
		System.out.println("\n");

		// Sign the input message!
		try {
			appletTest.ecSign(ecKeyPair, message);
		} catch (Exception e) {
			System.out.println("Caught Exception in Sign the input message: "
					+ e.toString());
		}
		System.out.println("\n");

		// verify Signature received from card
		ECPublicKey ecPublicKey = genEcPubKey();
		try {
			if (appletTest.ecVerify(ecSignData, ecPublicKey, message)) {
				System.out.println("EC: Signaure verification Successfully!!!");
			} else {
				System.out.println("EC: Signaure verification failed!");
			}
		} catch (Exception e) {
			System.out.println("Caught Exception in verification: "
					+ e.toString());
		}
		System.out.println("\n");

	}

}
