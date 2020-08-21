package com.demo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;

import com.fasterxml.jackson.databind.ObjectMapper;


/**
 * Hello world!
 *
 */
public class App 
{
	private static char[] password = null;
	private static String urlService = null;
	private static String authorization = null;
	private static String alias;
	
    public static void main( String[] args )
    {
		Security.addProvider(new BouncyCastleFipsProvider());
		cargarVariables();
		alias = Utils.dateTimeToStr(Utils.getNow());
		try 
		{
			createKeyStore();
			Certificado cert = createCertificate();
			String pkcs10 = createCSR(cert);
			List<X509Certificate> chain = sendApi(pkcs10);
			saveCertificate(cert, chain);
		} 
		catch (IOException | OperatorCreationException | GeneralSecurityException | CMSException e) {
			e.printStackTrace();
		}		
    }
    /**
     * 
     */
    public static void cargarVariables()
    {
    	Map<String, String> env = System.getenv();
    	for (String envName : env.keySet()) 
    	{
    		if ("KEYSTORE_PASSWORD".equals(envName)) {
    			password = env.get(envName).toCharArray();
    		}
    		else
    		if ("SERVICE_URL".equals(envName)) {
    			urlService = env.get(envName);
    		}
    		if ("SERVICE_AUTHORIZATION".equals(envName)) {
    			authorization = env.get(envName);
    		}
    	}
    	if (password == null) {
    		throw new RuntimeException("Falta la variable KEYSTORE_PASSWORD");
    	}
    	if (urlService == null) {
    		throw new RuntimeException("Falta la variable SERVICE_URL");
    	}
    	if (authorization == null) {
    		throw new RuntimeException("Falta la variable SERVICE_AUTHORIZATION");
    	}
    }
	/**
	 * 
	 */
	public static void createKeyStore() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
		File fileKeystore = new File("keystore.bks");
		if (fileKeystore.exists()) {
			FileInputStream fileKeyStore = new FileInputStream(fileKeystore);
			keyStore.load(fileKeyStore, password);
			fileKeyStore.close();
			return;			
		} else {
			keyStore.load(null, null);
		}
		FileOutputStream fos = new FileOutputStream("keystore.bks");
		System.out.println("SAVE KEYSTORE");
		keyStore.store(fos, password);
	}
	/**
	 * 
	 */
	public static Certificado createCertificate() throws CertIOException, OperatorCreationException, GeneralSecurityException
	{
		System.out.println("INIT KEY PAR");
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BCFIPS");
		kpGen.initialize(2048);
		System.out.println("GEN KEY PAR");
		KeyPair kp = kpGen.generateKeyPair();
		System.out.println("MAKE CERT");
		X509Certificate cert = Utils.makeV3Certificate(kp.getPrivate(), kp.getPublic());
		return new Certificado(cert,kp.getPrivate());
	}
	/**
	 * 
	 */
	public static String createCSR(Certificado certificado) throws OperatorCreationException, GeneralSecurityException, IOException 
	{
		System.out.println("CREATE CSR");
		PKCS10CertificationRequest csr = Utils.createPkcs10Request(certificado.getKey(), certificado.getCert());
		String pkcs10 = new String(Base64.getEncoder().encode(csr.getEncoded()));
		return pkcs10;
	}
	/**
	 * 
	 */
	private static List<X509Certificate> sendApi(String pkcs10) throws IOException, CMSException, CertificateException 
	{
		System.out.println("CONNECT SERVER");
		URL url = new URL(urlService);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("POST");
		con.setRequestProperty("Content-Type", "application/json; utf-8");
		con.setRequestProperty("Authorization",authorization);
		con.setRequestProperty("Accept", "application/json");
		con.setDoOutput(true);
		String jsonInputString = "{\"operacion\": \"firmar_csr\", \"csr_base64\": \" " + pkcs10 + "\"}";
		try (OutputStream os = con.getOutputStream()) {
			byte[] input = jsonInputString.getBytes("utf-8");
			os.write(input, 0, input.length);
		}
		System.out.println("RESPONSE SERVER");
		String respCsr = null;
		try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "utf-8"))) {
			StringBuilder response = new StringBuilder();
			String responseLine = null;
			while ((responseLine = br.readLine()) != null) {
				response.append(responseLine.trim());
			}
			respCsr = response.toString();
		}
		ObjectMapper mapper = new ObjectMapper();
		ResponseCsr responseCsr = mapper.readValue(respCsr, ResponseCsr.class);
		if (responseCsr.isSuccess()) 
		{
			String pkcs7 = responseCsr.getPkcs7_der_base64();
			byte[] data = Base64.getDecoder().decode(pkcs7);
			
			CMSSignedData s = new CMSSignedData(data);
			JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
			Store<X509CertificateHolder> certStore = s.getCertificates();
			Collection<X509CertificateHolder> matches = certStore.getMatches(null);
            List<X509Certificate> chainCertificate = new ArrayList<>();
            for (X509CertificateHolder certificateHolder : matches)
            {
                X509Certificate certificate = certificateConverter.getCertificate(certificateHolder);
            	chainCertificate.add(0,certificate);
            }
            return chainCertificate;
			
		} else {
			throw  new IOException("ERROR AL ENVIAR EL CSR");
		}
	}
	/**
	 * 
	 */
	public static void saveCertificate(Certificado cert, List<X509Certificate> xchain) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException
	{
		KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
		File fileKeystore = new File("keystore.bks");
		FileInputStream fileKeyStore = new FileInputStream(fileKeystore);
		keyStore.load(fileKeyStore, password);		
		Certificate chain [] = new Certificate[xchain.size()];
		chain = (Certificate[]) xchain.toArray(chain);
		keyStore.setKeyEntry(alias, cert.getKey(), password, chain);
		FileOutputStream fos = new FileOutputStream("keystore.bks");
		System.out.println("SAVE KEYSTORE END");
		keyStore.store(fos, password);
	}
}
