package crypto;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

public class Voter {
    private static KeyPair voterKeyPair;
    private static PublicKey raPublicKey;
    private static PublicKey vaPublicKey;
    private static PrivateKey voterPrivateKey;
    
    static {
    	try {
    		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    		keyGen.initialize(2048);
    		voterKeyPair = keyGen.generateKeyPair();
    		voterPrivateKey = voterKeyPair.getPrivate();
    		
    		raPublicKey = keyGen.generateKeyPair().getPublic();
    		vaPublicKey = keyGen.generateKeyPair().getPublic();
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    }
    
    public static void sendVote(String voterID) throws Exception {
    	Socket raSocket = new Socket("localhost", 5001);
    	OutputStream raOut = raSocket.getOutputStream();
    	InputStream raIn = raSocket.getInputStream();
    	
    	byte[] encryptedID = CryptoUtils.encrypt(voterID, raPublicKey);
    	raOut.write(encryptedID);
    	raOut.flush();
    	
    	byte[] tokenBytes = raIn.readNBytes(256);
    	String token = CryptoUtils.decrypt(tokenBytes, voterPrivateKey);
    	System.out.println(voterID + " received token: " + token);
    	raSocket.close();
    	
    	String vote = "Yes";
    	byte[] encryptedVote = CryptoUtils.encrypt(vote, vaPublicKey);
    	
    	String hashedVote = CryptoUtils.hash(vote);
    	byte[] signedHashedVote = CryptoUtils.sign(hashedVote, voterPrivateKey);
    	
    	byte[] signedToken = CryptoUtils.sign(token, voterPrivateKey);
    	
    	Socket vaSocket = new Socket("localhost", 5002);
    	ObjectOutputStream out = new ObjectOutputStream(vaSocket.getOutputStream());
    	
    	out.writeObject(encryptedVote);
    	out.writeObject(signedHashedVote);
    	out.writeObject(signedToken);
    	out.writeObject(voterKeyPair.getPublic());
    	out.flush();
    	
    	System.out.println(voterID + " sent vote and signatures to VA.");
    	vaSocket.close();
    }
}