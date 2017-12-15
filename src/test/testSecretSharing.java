package test;

import java.math.BigInteger;
import java.util.ArrayList;

import progetto4.*;

public class testSecretSharing {

	public static void main(String[] args) {
		int k = 1;
		int n= 4;

		SecretSharing ss = new SecretSharing();
		
		String text = " malesuada erat. Nulla ut malesuada purus. In sit amet eleifend ipsum. Fusce iaculis efficitur malesuada. Nulla et sollicitudin lectus, a tincidunt tellus. Aenean id posuere enim. Mauris eros lectus, dignissim rutrum nisi at, vulputate dignissim ligula. Maecenas sed bibendum magna. Curabitur vel mauris odio. Pellentesque pulvinar imperdiet augue vitae volutpat. Phasellus auctor turpis nulla, vel consequat mi varius id. Ut nec ipsum eu purus fringilla interdum ut sit amet tortor.\r\n" + 
				"\r\n" + 
				"Duis vitae pe";
		byte[] byteText = text.getBytes();
		
		BigInteger secret = new BigInteger(byteText);
		ss.setSecret(secret);
		System.out.println("Segreto settato...  "  + secret);

		ArrayList<Entrant> informations = new ArrayList<Entrant>();
		BigInteger p = null;
		try {
			//p = ss.generatePartialInformations(k, n, informations);
			p = new BigInteger("211277964997818262576305487975006791392031781252751575104464482156666385415210050590518242479333926131045319044093307050969742912718295673021745431696446741077433639690296435242106434038685979270618639524221268237492827789055053284738521515927155135597123558744606857895242745516948094201864843843315702118315009761182631008929824022834670888085907362144370439133457750806282559136026325543527280063282812325625424197572075522286425033968165343306874353244313373471478499759579790144630077913011136387443222269987693769028516203229051885791273527590846333076077446357591341287038114760181377065761128234693687130594405907710886720909289476665135520025875623730335275587350148632670565132130853747197945369151251291882066605092017072904760955633532026765814000219066872624489874612136901244700201314770154682190329433692422609509940144511326152593333981654636472583927194296111309144364997974452296239333770912085074858305073012137651102284916252073980860590640560334526541392766362203014315007959542029690649186071161936895246187365270986156268377406459786641662566546286556625972071070476022399240283937620902824818425136189932670103066902504780377096485022547828698595746662366638227255312284787768715461");
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
		 
		byte[] rec_seq = secret_r.toByteArray();
		System.out.println(text);
		System.out.println(new String(rec_seq));
		

	}

}
