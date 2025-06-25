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
    
    public static void sendVote(
    		String voterID,
    		KeyPair voterKeyPair,
            PublicKey raPublicKey,
            PublicKey vaPublicKey
    ) throws Exception {
    	Socket raSocket = new Socket("localhost", 5001);
    	ObjectOutputStream raOut = new ObjectOutputStream(raSocket.getOutputStream());
    	ObjectInputStream raIn = new ObjectInputStream(raSocket.getInputStream());
    	
    	byte[] encryptedID = CryptoUtils.encrypt(voterID, raPublicKey);
    	raOut.writeObject(encryptedID);
    	raOut.writeObject(voterKeyPair.getPublic());
    	raOut.flush();
    	
    	PrivateKey voterPrivateKey = voterKeyPair.getPrivate();
    	
    	byte[] tokenBytes = (byte[]) raIn.readObject();
    	String token = CryptoUtils.decrypt(tokenBytes, voterPrivateKey);
    	System.out.println(voterID + " received token: " + token);
    	raSocket.close();
    	
    	String vote = Math.random() > 0.5 ? "Yes" : "No";
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