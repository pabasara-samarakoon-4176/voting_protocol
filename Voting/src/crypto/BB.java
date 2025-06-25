package crypto;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class BB {
	public static void main(String[] args) throws IOException {
		ServerSocket bbSocket = new ServerSocket(5003);
        System.out.println("BB started. Waiting for VA...");
        
        PrivateKey bbPrivateKey = KeyManager.getPrivateKey("BB");
        PublicKey bbPublicKey = KeyManager.getPublicKey("BB");

        while (true) {
            Socket vaSocket = bbSocket.accept();
            new Thread(new BBHandler(vaSocket, bbPrivateKey)).start();
        }

	}

}

class BBHandler implements Runnable {
	private Socket socket;
	private PrivateKey bbPrivateKey;
	
	public BBHandler(Socket socket, PrivateKey bbPrivateKey) {
		this.socket = socket;
		this.bbPrivateKey = bbPrivateKey;
	}
	
	public void run() {
		try (
			ObjectInputStream in = new ObjectInputStream(socket.getInputStream())	
		) {
			byte[] encryptionHash = (byte[]) in.readObject();
			String hash = CryptoUtils.decrypt(encryptionHash, bbPrivateKey);
			System.out.println("BB: Vote hash posted on board -> " + hash);
			socket.close();
		} catch (Exception e) {
			System.out.println("BB: Failed to process vote.");
			e.printStackTrace();
		}
	}
}
