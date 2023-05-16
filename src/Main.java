import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("\n───────────────────────────────────────────────────────────────────────────────");
        System.out.println("EJERCICIO 1");
        System.out.println("───────────────────────────────────────────────────────────────────────────────");
        KeyPair keyPair = UtilitatsXifrar.randomGenerate(1024);
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.print("Introduce un mensaje a cifrar: ");
        String mensaje = scanner.nextLine();
        byte[] cifrarDatos = UtilitatsXifrar.encryptData(mensaje.getBytes(), publicKey);
        byte[] descifrarDatos = UtilitatsXifrar.decryptData(cifrarDatos, privateKey);
        String mensajeDescifrado = new String(descifrarDatos);
        String mensajeCifrado = new String(cifrarDatos);
        System.out.println("Mensaje cifrado: "+ mensajeCifrado);
        System.out.println("Mensaje descifrado: "+mensajeDescifrado);


        System.out.println("\n───────────────────────────────────────────────────────────────────────────────");
        System.out.println("EJERCICIO 1.2.1");
        System.out.println("───────────────────────────────────────────────────────────────────────────────");
        KeyStore ks = UtilitatsXifrar.loadKeyStore("/home/dam2a/mykeystore2.jks", "usuario");
        System.out.println("Tipo de keystore: "+ ks.getType());
        int size = ks.size();
        System.out.println("Tamaño del keystore: " + size);
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias de la clave: " + alias);
        }
        String alias = "mykeypair";
        Certificate cert = ks.getCertificate(alias);
        System.out.println("Certificado de la clave " + alias + ": " + cert.toString());
        String aliasClaves = "mykeypair";
        Key key = ks.getKey(aliasClaves, "usuario".toCharArray());
        String algorithm = key.getAlgorithm();
        System.out.println("Algoritmo de cifrado de la clave " + aliasClaves + ": " + algorithm);

        System.out.println("\n───────────────────────────────────────────────────────────────────────────────");
        System.out.println("EJERCICIO 1.2.2");
        System.out.println("───────────────────────────────────────────────────────────────────────────────");
        SecretKey secretKey = UtilitatsXifrar.keygenKeyGeneration(256);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection("usuario".toCharArray());
        ks.setEntry("mykeypair", secretKeyEntry, entryPassword);
        ks.store(new FileOutputStream("/home/dam2a/mykeystore.jks"), "usuario".toCharArray());


        System.out.println("\n───────────────────────────────────────────────────────────────────────────────");
        System.out.println("EJERCICIO 1.2.3");
        System.out.println("───────────────────────────────────────────────────────────────────────────────");
        PublicKey publicKeyCer = UtilitatsXifrar.getPublicKey("/home/dam2a/my_signed_certificate.cer");
        System.out.println("Algoritmo: " + publicKeyCer.getAlgorithm());
        System.out.println("Formato: " + publicKeyCer.getFormat());
        System.out.println("Valor: " + Arrays.toString(publicKeyCer.getEncoded()));


        System.out.println("\n───────────────────────────────────────────────────────────────────────────────");
        System.out.println("EJERCICIO 1.2.4");
        System.out.println("───────────────────────────────────────────────────────────────────────────────");
        KeyStore ks4 = KeyStore.getInstance("PKCS12");
        char[] password = "usuario".toCharArray();
        ks4.load(new FileInputStream("/home/dam2a/mykeystore2.jks"), password);
        // Obtener la clave pública y mostrarla por pantalla
        PublicKey publicKey4 = UtilitatsXifrar.getPublicKey(ks4, "mykeypair", "usuario");
        System.out.println(publicKey4);


        System.out.println("\n───────────────────────────────────────────────────────────────────────────────");
        System.out.println("EJERCICIO 1.2.5");
        System.out.println("───────────────────────────────────────────────────────────────────────────────");
        PrivateKey privateKey5 = UtilitatsXifrar.getPrivateKeyFromKeystore();
        byte[] data = "Estos son los datos a firmar".getBytes();
        byte[] signature = UtilitatsXifrar.signData(data, privateKey5);
        System.out.println("La firma es: " + new String(signature));


        System.out.println("\n───────────────────────────────────────────────────────────────────────────────");
        System.out.println("EJERCICIO 1.2.6");
        System.out.println("───────────────────────────────────────────────────────────────────────────────");
        PublicKey publicKey6 = UtilitatsXifrar.getPublicKey(ks4, "mykeypair", "usuario");
        byte[] data6 = "Estos son los datos que se firmaron".getBytes();
        byte[] signature6 =  UtilitatsXifrar.signData(data, privateKey5);
        boolean isValid = UtilitatsXifrar.validateSignature(data6, signature6, publicKey6);
        if (isValid) {
            System.out.println("La firma es válida");
        } else {
            System.out.println("La firma NO es válida");
        }


        System.out.println("\n───────────────────────────────────────────────────────────────────────────────");
        System.out.println("EJERCICIO 2");
        System.out.println("───────────────────────────────────────────────────────────────────────────────");

        KeyPair keyPair2 = UtilitatsXifrar.randomGenerate(1024);
        PublicKey publicKey2 = keyPair2.getPublic();
        PrivateKey privateKey2 = keyPair2.getPrivate();
        String textToEncrypt = "Quiero acabar el ciclo YAAAAA";
        byte[] dataToEncrypt = textToEncrypt.getBytes();
        byte[][] encryptedData = UtilitatsXifrar.encryptWrappedData(dataToEncrypt, publicKey2);
        byte[] decryptedData = UtilitatsXifrar.decryptWrappedData(encryptedData, privateKey2);
        String decryptedText = new String(decryptedData);
        System.out.println("Texto original: " + textToEncrypt);
        System.out.println("Texto desencriptado: " + decryptedText);
    }

}