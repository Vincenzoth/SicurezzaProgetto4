package test;

import java.math.BigInteger;
import java.util.ArrayList;

import progetto4.*;

public class testSecretSharing {

	public static void main(String[] args) {
		int k = 80;
		int n= 100;

		SecretSharing ss = new SecretSharing();

		BigInteger secret = new BigInteger("15");
		ss.setSecret(secret);
		System.out.println("Segreto settato...  "  + secret);

		ArrayList<Entrant> informations = new ArrayList<Entrant>();
		BigInteger p = null;
		try {
			//p = ss.generatePartialInformations(k, n, informations);
			p = new BigInteger("103");
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
		System.out.println("Segreto ricostruito: " + secret_r);

	}

}
