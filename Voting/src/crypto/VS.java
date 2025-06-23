package crypto;

import java.io.*;
import java.net.*;

public class VS {

	public static void main(String[] args) throws IOException {
		ServerSocket vsSocket = new ServerSocket(5004);
        System.out.println("VS started. Waiting for VA...");

        while (true) {
            Socket va = vsSocket.accept();
            BufferedReader in = new BufferedReader(new InputStreamReader(va.getInputStream()));
            String vote = in.readLine();
            System.out.println("VS received vote: " + vote);
            va.close();
        }

	}

}
