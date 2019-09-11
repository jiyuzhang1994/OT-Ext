import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.lang.*;
import java.util.*;
import java.security.*;
import java.math.*;
import java.lang.Exception.*;
import java.net.*;

public class Receiver {
	/* Extension Parameters */
	int[] choices;				//Receiver's m choices
	int[][] randMatrix; 		//random generated matrix T
	int k;						//security parameter k
	MessageDigest rdOracle;		//random oracle H, we use SHA-1 hash function
	String[][] cText;			//ciphertext received

	/* (k, m)-OT protocol parameters */

	/* 2048-bit MODP Group;
	This group is assigned id 14.
	This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
	The generator is: 2. 
	*/
	String hexStr = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
	BigInteger bigP = new BigInteger(hexStr, 16);
	BigInteger generator = new BigInteger(Integer.toString(2));

	BigInteger[] c;					//generate an array of group elements 
	BigInteger[][] pkeys; 			//received from sender
	BigInteger[][] rkeys; 			//randomly generated [r0, r1]
	BigInteger[][] rkeysInGroup;	//generator^rkeys
	String[][] encryptedMat;

	public Receiver(int[] rInput, int parameter) {
		choices = rInput;
		k = parameter;
	}

	/* (k, m)-OT protocol methods 
	the protocol consists of a 4-tuple:
	generateC() from receiver
	genePK() from sender
	enc() from receiver
	dec() from sender
	*/

	public BigInteger pow(BigInteger base, BigInteger expnt) {
		BigInteger res = base.modPow(expnt, bigP);
		return res;
	}

	public void generateC () {
		BigInteger[] res = new BigInteger[k];
		for (int i=0; i<k; i++) {
			res[i] = new BigInteger(2048, new Random());
		}
		this.c = res;
	}

	public void geneBigRPairs() {
		BigInteger[][] rs = new BigInteger[k][2];
		BigInteger[][] rsIG = new BigInteger[k][2];
		for (int i=0; i<k; i++) {
			rs[i][0] = new BigInteger(2048, new Random());
			rsIG[i][0] = pow(generator, rs[i][0]);
			rs[i][1] = new BigInteger(2048, new Random());
			rsIG[i][1] = pow(generator, rs[i][1]);
		}
		this.rkeys = rs;
		this.rkeysInGroup = rsIG;
	}

	public void encryptMatrix() {
		try {
			String[][] txt = new String[k][2];
			for (int i=0; i<k; i++) {
				BigInteger gr0 = rkeysInGroup[i][0];
				BigInteger gr1 = rkeysInGroup[i][1];

				BigInteger pk0 = this.pow(pkeys[i][0], rkeys[i][0]);
				BigInteger pk1 = this.pow(pkeys[i][1], rkeys[i][1]);

				byte[] h0 = this.rdOracle.digest(pk0.toByteArray());
				byte[] h1 = this.rdOracle.digest(pk1.toByteArray());

				String t0 = "";
				String t1 = "";
				for (int j=0; j<this.randMatrix.length; j++) {
					t0 += Integer.toString(this.randMatrix[j][i]);
					t1 += Integer.toString(this.randMatrix[j][i] ^ this.choices[j]);
				}

				byte[] t0Byte = t0.getBytes("ISO-8859-1");
				byte[] t1Byte = t1.getBytes("ISO-8859-1");

				byte[] enc0Byte = new byte[t0Byte.length];
				byte[] enc1Byte = new byte[t1Byte.length];

				for (int j=0; j<t0Byte.length; j++) {
					enc0Byte[j] = (byte) (t0Byte[j]^h0[j]);
					enc1Byte[j] = (byte) (t1Byte[j]^h1[j]);
				}

				txt[i][0] = new String(enc0Byte, "ISO-8859-1");
				txt[i][1] = new String(enc1Byte, "ISO-8859-1");
			}
			this.encryptedMat = txt;
		}catch (UnsupportedEncodingException en) {
			System.out.println(en);
		}
	}



	/* Extension methods */
	// generate m by k random matrix
	public void generateT() {
		int m = choices.length;
		Random rd = new Random();
		int[][] mat = new int[m][k];
		for (int i=0; i<m; i++) {
			for (int j=0; j<k; j++) {
				mat[i][j] = rd.nextBoolean() == true? 1 : 0;
			}
		}
		randMatrix = mat;
	}

	//use SHA-1 as random Oracle
	public void geneOracle() {
		try {
			rdOracle = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e);
		}
	}

	//decryption
	public String[] dec() {
		String[] output = new String[this.choices.length];
		try {
			for (int i=0; i<this.cText.length; i++) {
				int[] t = this.randMatrix[i];	//t_i : the ith row of T
				String key = "";				//string representation of t
				for (int k : t) {
					key += Integer.toString(k);
				}
				byte[] keyByte = this.rdOracle.digest(key.getBytes("ISO-8859-1"));
				byte[] k = new byte[20];


				String y = this.cText[i][this.choices[i]];   //receiver's selection of message
				byte[] yByte = y.getBytes("ISO-8859-1");
				for (int j=0; j<20; j++) {
					k[j] = (byte) (yByte[j]^keyByte[j]);
				}
				output[i] = new String(k, "ISO-8859-1");
    		}
		} catch (UnsupportedEncodingException en) {
			System.out.println(en);
		}
		return output;
	}

	public static void main(String[] args) {


		String serverName = "localhost";
		int port = 5000;

		try {
        	System.out.println("Connecting to " + serverName + " on port " + port + "..." + "\n");
        	Socket client = new Socket(serverName, port);
        	System.out.println("Just connected to " + client.getRemoteSocketAddress() + "\n");

        	ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream());
        	ObjectInputStream in = new ObjectInputStream(client.getInputStream());

        	//test case initiation
        	Receiver bob = new Receiver(new int[] {0, 1, 1, 0, 1, 0}, 10);
        	System.out.println("Receiver\'s choices are: ");
        	System.out.println(Arrays.toString(bob.choices) + "\n");
        	//generate m by k random matrix
        	bob.generateT();

        	try {
				//generate oracle;
        		bob.geneOracle();

        		//Execute OT(k, m): execute OT(1, m) for k times
        		System.out.println("\n--- Starting to execute the (k, m)-OT primitive ... ---\n");
        		bob.generateC();
        		out.writeObject(bob.c);
        		bob.pkeys = (BigInteger[][]) in.readObject();
        		bob.geneBigRPairs();
        		bob.encryptMatrix();
        		out.writeObject(bob.rkeysInGroup);
        		out.writeObject(bob.encryptedMat);

        		System.out.println("bob sends excrypted k pairs of matrix columns of T: ");
        		for (int i=0; i<bob.encryptedMat.length; i++) {
					System.out.println("Pairs" + (i+1) + "(0) :     " + bob.encryptedMat[i][0]);
					System.out.println("Pairs" + (i+1) + "(1) :     " + bob.encryptedMat[i][1]);
        		}

        		System.out.println("--- End (k, m)-OT primitive ---\n");



        		/* Abandonded cheating  OT(k, m) */
        		/*
        		int[] s = (int[]) in.readObject();
        		int[][] prQ = new int[bob.randMatrix.length][bob.randMatrix[0].length];
        		for (int i=0; i<bob.randMatrix.length; i++) {
        			if (bob.choices[i] == 1) {
        				for (int j=0; j<s.length; j++) {
        					prQ[i][j] = bob.randMatrix[i][j]^s[j];
        				}
        			}else {
        				for (int j=0; j<s.length; j++) {
        					prQ[i][j] = bob.randMatrix[i][j];
        				}
        			}
        		}
        		out.writeObject(prQ);
        		*/


        		//receive ciphertext and decrypt
        		bob.cText = (String[][]) in.readObject();
        		String[] res = bob.dec();

				//print output
				System.out.println("Receiver\'s output includes: ");
        		for (int i=0; i<res.length; i++) {
        			System.out.println("Pairs" + (i+1) + "(" + bob.choices[i] + ") : " + res[i]);
        		}
        		
        		//End Connection
        		client.close();
        		in.close();
        	} catch (ClassNotFoundException c) {
        		System.out.println(c);
        	}
    	} catch (IOException e) {
    		System.out.println(e);
    	}
	}
}




