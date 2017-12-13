package test;

import java.math.BigInteger;
import java.util.ArrayList;

import progetto4.*;

public class testSecretSharing {

	public static void main(String[] args) {
		SecretSharing ss = new SecretSharing();
		
		BigInteger secret = new BigInteger("7");
		ss.setSecret(secret);
		System.out.println("Segreto settato...  "  + secret);
		
		ArrayList<Entrant> informations = new ArrayList<Entrant>();
		BigInteger p = null;
		try {
			p = ss.generatePartialInformations(3, 6, informations);
			//p = new BigInteger("17");
			//ss.generatePartialInformations(3, 6, p,  informations);
		
		System.out.println("Informazioni parziali generate...");
		System.out.println("Il primo generato è: " + p);
		System.out.println(informations);
		} catch (SecretSharingException e) {
			System.err.println("Errore nella generazione dello shema");
		}
		
		
		ArrayList<Entrant> recInformations = new ArrayList<Entrant>();
		recInformations.add(informations.get(0));
		recInformations.add(informations.get(5));
		recInformations.add(informations.get(4));
		
		
		BigInteger secret_r = ss.computeSecret(recInformations);
		System.out.println("Segreto ricostruito: " + secret_r);

	}

}
