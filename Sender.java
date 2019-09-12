import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.lang.*;
import java.util.*;
import java.security.*;
import java.math.*;
import java.lang.Exception.*;
import java.net.*;

public class Sender {
	/* Extension Parameters */
	String[][] msgs;          //m pairs of messages [x_10, x_11] ... [x_m0, xm1]
	int k;	                  //security parameter k
	int[] randVec;            //the k-bit random vector s of Sender
	int[][] prQ;              //pseudo-random m by k matrix Q received by Sender
	MessageDigest rdOracle;   //random oracle H, we use SHA-1 hash function 

	/* (k, m)-OT protocol parameters */

	/* 2048-bit MODP Group;
	This group is assigned id 14.
	This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
	The generator is: 2. 
	*/
	String hexStr = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
	BigInteger bigP = new BigInteger(hexStr, 16);
	BigInteger generator = new BigInteger(Integer.toString(2));

	int[] delta; 				//Sender's choice in k,m OT delta = randVec
	BigInteger[][] pkeys;		//public key pairs generated
	BigInteger[] bigK;		//generator^bigK is PK_delta
	BigInteger c[];			//group member from receiver
	BigInteger[][] rkeysInGroup;	//generator^rkeys
	String[][] encryptedMat;

	public Sender(String[][] sInput, int parameter) {
		for (int i=0; i<sInput.length; i++) {
			for (String str : sInput[i]) {
				if (str.length() != 20) {
					throw new IllegalArgumentException("Messages must be of length 20");
				}
			}
		}
		msgs = sInput;
		k = parameter;
	}


	/* (k, m)-OT protocol methods */

	/*
	the protocol consists of a 4-tuple:

	generateC() from receiver
	genePK() from sender
	decryptMatrix() from receiver
	encryptMatrix() from sender
	*/

	//base^expnt mod bigP
	public BigInteger pow(BigInteger base, BigInteger expnt) {
		BigInteger res = base.modPow(expnt, bigP);
		return res;
	}

	//generate random k used to compute key
	public BigInteger[] geneK() {
		BigInteger[] theK = new BigInteger[k];
		for (int i=0; i<k; i++) {
			theK[i] = new BigInteger(2048, new Random());
		}
		return theK;
	}

	//generate public keys [PK_0, PK_1]
	public void genePK() {
		bigK = this.geneK();
		BigInteger[][] keys = new BigInteger[k][2];
		for (int i=0; i<k; i++) {
			if (randVec[i] == 0) {
				keys[i][0] = this.pow(generator, bigK[i]);
				keys[i][1] = this.c[i].multiply(keys[i][0].modInverse(bigP)).mod(bigP);
			}else {
				keys[i][1] = this.pow(generator, bigK[i]);
				keys[i][0] = this.c[i].multiply(keys[i][1].modInverse(bigP)).mod(bigP);
			}
		}
		pkeys = keys;
	}

	//decrypt the random matrix Q received from bob.
	public void decryptMatrix() {
		try {
			int[][] res = new int[this.msgs.length][k];
			for (int i=0; i<this.encryptedMat.length; i++) {
				String y = this.encryptedMat[i][this.randVec[i]];
				BigInteger gr = this.rkeysInGroup[i][this.randVec[i]];
				BigInteger pk = this.pow(gr, this.bigK[i]);

				byte[] h = this.rdOracle.digest(pk.toByteArray());
				byte[] yByte = y.getBytes("ISO-8859-1");
				byte[] decByte = new byte[yByte.length];
				for (int j=0; j<decByte.length; j++) {
					decByte[j] = (byte) (yByte[j]^h[j]);
				}

				String dec = new String(decByte, "ISO-8859-1");
				for (int j=0; j<dec.length(); j++) {
					res[j][i] = Character.getNumericValue(dec.charAt(j));
				}
			}
			this.prQ = res;

		} catch (UnsupportedEncodingException en) {
			System.out.println(en);
		}
	}



	/* Extension Methods */

	//generate k-bit random vector s
	public void generateS() {
		Random rd = new Random();
		int[] arr = new int[k];
		for (int i=0; i<k; i++) {
			arr[i] = rd.nextBoolean() == true? 1 : 0;
		}
		randVec = arr;
	}

	//use SHA-1 as random Oracle
	public void geneOracle() {
		try {
			rdOracle  = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e);
		}
	}

	//encryption
	public String[][] enc() {
		String[][] cText = new String[msgs.length][2];

		try {
			for (int i=0; i<cText.length; i++) {
				/* encrypt x_i0 */
				byte[] x0 = this.msgs[i][0].getBytes("ISO-8859-1");
				int[] q = this.prQ[i];  //q_i : the ith row of Q
				String key0 = ""; 		 //string representation of q_i
				for (int k : q) {
					key0 += k;
				}
				//compute hashes keys
				byte[] key0Byte = this.rdOracle.digest(key0.getBytes("ISO-8859-1"));

				//xor key and messages
				byte[] k0 = new byte[20];
				for (int j=0; j<20; j++) {
					k0[j] = (byte) (key0Byte[j]^x0[j]);
				}
				cText[i][0] = new String(k0, "ISO-8859-1");

				/* encrypt x_i1 */
				byte[] x1 = this.msgs[i][1].getBytes("ISO-8859-1");
				int[] xor = new int[q.length]; // q_i xor s
				String key1 = ""; 						  // string representaiton of q_i xor s
				for (int j=0; j<xor.length; j++) {
					xor[j] = q[j]^this.randVec[j];
				}
				for (int k : xor) {
					key1 += Integer.toString(k);
				}
				//compute hashes keys
				byte[] key1Byte = this.rdOracle.digest(key1.getBytes("ISO-8859-1"));

				//xor key and messages
				byte[] k1 = new byte[20];
				for (int j=0; j<20; j++) {
					k1[j] = (byte) (key1Byte[j]^x1[j]);
				}
				cText[i][1] = new String(k1, "ISO-8859-1");
			}
		} catch (UnsupportedEncodingException en) {
			System.out.println(en);
		}
		return cText;
	}

	public static void main(String[] args) {
		
		try{
			ServerSocket serverSocket = new ServerSocket(5000);
			serverSocket.setSoTimeout(100000);
			try {
				System.out.println("Waiting for client on port " + 
					serverSocket.getLocalPort() + "..." + "\n");
				Socket server = serverSocket.accept();

				System.out.println("Just connected to " + server.getRemoteSocketAddress() + "\n");
				ObjectInputStream in = new ObjectInputStream(server.getInputStream());
				ObjectOutputStream out = new ObjectOutputStream(server.getOutputStream());

				//test case initialization; messages must be pairs of strings of length 20;
				String[][] sInput = new String[7][2];
				sInput[0] = new String[] {"Angel012345678901234", "Devil012345678901234"}; 
				sInput[1] = new String[] {"Dog01234567890123456", "Cat01234567890123456"}; 
				sInput[2] = new String[] {"Apple012345678901234", "Banana01234567890123"}; 
				sInput[3] = new String[] {"Red01234567890123456", "Blue0123456789012345"}; 
				sInput[4] = new String[] {"Pizza012345678901234", "HotDog01234567890123"};
				sInput[5] = new String[] {"Coke0123456789012345", "Spirit01234567890123"};
				sInput[6] = new String[] {"IcedLatte01234567891", "Mocha012345678912345"};

				Sender alice = new Sender(sInput, 5);
				System.out.println("The protocol extends k = " + alice.k + " OTs to m = " + alice.msgs.length + " OTs \n" );
				System.out.println("Sender\'s input includes: ");
				for (int i=0; i<sInput.length; i++) {
					System.out.println(Arrays.toString(sInput[i]));
				}

				//generate random oracle;
				alice.geneOracle();

				//Execute OT(k, m): get prQ matrix from receiver;
				System.out.println("\n--- Starting to execute the (k, m)-OT primitive ... ---");
				alice.generateS();
				alice.c = (BigInteger[]) in.readObject();
				alice.genePK();
				out.writeObject(alice.pkeys);

				alice.rkeysInGroup = (BigInteger[][]) in.readObject();
				alice.encryptedMat = (String[][]) in.readObject();
				alice.decryptMatrix();

				System.out.println("the m by k matrix Q received by alice is : ");
				for (int i=0; i<alice.prQ.length; i++) {
					System.out.println(Arrays.toString(alice.prQ[i]));
				}

				System.out.println("--- End (k, m)-OT primitive. --- \n");

				// Abandonded cheating  OT(k, m)
				/*
				out.writeObject(alice.randVec);
				alice.prQ = (int[][]) in.readObject();
				*/


				//encrypt msgs and send it
				String[][] cText = alice.enc();

				//test
				System.out.println("\nSender sends ciphertext: " );
				for (int i=0; i<cText.length; i++) {
					System.out.println("Pairs" + (i+1) + "(0) :     " + cText[i][0]);
					System.out.println("Pairs" + (i+1) + "(1) :     " + cText[i][1] + "\n");
				}

				out.writeObject(cText);


				//End Connection
				server.close();
				in.close();
			} catch (SocketTimeoutException s) {
				System.out.println("Socket timed out!");
			} catch (ClassNotFoundException c) {
				System.out.println(c);
			} 
		} catch (IOException i) {
			System.out.println(i);
		}
	}
}