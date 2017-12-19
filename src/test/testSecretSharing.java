package test;

import java.math.BigInteger;
import java.util.ArrayList;

import progetto4.*;


public class testSecretSharing {

	public static void main(String[] args) {
		int k = 85;
		int n= 100;

		SecretSharing ss = new SecretSharing();
		
		String text = "Questa stringa è un segreto!!!!";
		byte[] byteText = text.getBytes();
		
		BigInteger secret = new BigInteger(byteText);
		ss.setSecret(secret);
		System.out.println("Segreto settato...  "  + secret);

		ArrayList<Entrant> informations = new ArrayList<Entrant>();
		BigInteger p = null;
		try {
			// possiamo scegliere di far generare a caso un primo per lo schema di shamir...
			p = ss.generatePartialInformations(k, n, informations);
			
			// ...oppure possiamo decidere di utilizzare un primo a scelta
			p = new BigInteger("368825414839026694656526417537712528639136378032700719406517620121630789757");
			ss.generatePartialInformations(k, n, p,  informations);

			System.out.println("Informazioni parziali generate...");
			System.out.println("Il primo generato è: " + p);
			System.out.println(informations);
		} catch (SecretSharingException e) {
			System.err.println(e.getMessage());
		}


		ArrayList<Entrant> recInformations = new ArrayList<Entrant>();
		int i;
		for( i = 0; i < k; i++) {
			recInformations.add(informations.get(i));
		}

		BigInteger secret_r = ss.computeSecret(recInformations);
		System.out.println("Segreto ricostruito bigInteger: " + secret_r);
		 
		System.out.println("------");
		byte[] rec_seq = secret_r.toByteArray();
		System.out.println("Segreto ricostruito : " + new String(rec_seq));
		System.out.println("  Segreto originale : " + text);
		

	}

}
