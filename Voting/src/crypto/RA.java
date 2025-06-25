package crypto;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

public class RA {
	
	public static void main(String[] args) throws IOException {
		ServerSocket serverSocket = new ServerSocket(5001);
		System.out.println("RA started. Waiting for voters...");
		
		PrivateKey raPrivateKey = KeyManager.getPrivateKey("RA");
		
		while (true) {
			Socket clientSocket = serverSocket.accept();
			new Thread(new RAHandler(clientSocket, raPrivateKey)).start();
		}
	}

}

class RAHandler implements Runnable {
    private Socket socket;
    private PrivateKey raPrivateKey;

    public RAHandler(Socket socket, PrivateKey raPrivateKey) {
        this.socket = socket;
        this.raPrivateKey = raPrivateKey;
    }

    public void run() {
        try (
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())
        ) {
            byte[] encryptedID = (byte[]) in.readObject();
            PublicKey voterPublicKey = (PublicKey) in.readObject();


            String voterID = CryptoUtils.decrypt(encryptedID, raPrivateKey);
            System.out.println("RA received ID: " + voterID);

            String token = CryptoUtils.hash(voterID);

            byte[] encryptedToken = CryptoUtils.encrypt(token, voterPublicKey);

            out.writeObject(encryptedToken);
            out.flush();

            System.out.println("RA sent encrypted token to voter.");
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
