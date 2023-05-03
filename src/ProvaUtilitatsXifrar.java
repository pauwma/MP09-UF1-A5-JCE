import javax.crypto.SecretKey;
import java.util.Arrays;

public class ProvaUtilitatsXifrar {

    public static void main(String[] args) throws Exception {
        // ! 5. Xifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1
        System.out.println("\n───────────────────────────────────────────────────────────────────────────────");
        System.out.println("  ifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1");
        System.out.println("───────────────────────────────────────────────────────────────────────────────");

        String text = "Aquest és un text de prova";
        SecretKey key = UtilitatsXifrar.keygenKeyGeneration(256);
        byte[] encryptedData = UtilitatsXifrar.encryptData(text.getBytes(), key);
        byte[] decryptedData = UtilitatsXifrar.decryptData(encryptedData, key);
        String decryptedText = new String(decryptedData);
        System.out.println("Text desxifrat amb clau generada amb keygenKeyGeneration: " + decryptedText);

        // ! 6. Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas.
        System.out.println("\n────────────────────────────────────────────────────────────────────────────────────────────────────────────");
        System.out.println("  6. Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas.");
        System.out.println("────────────────────────────────────────────────────────────────────────────────────────────────────────────");
        String password = "contrasenya";
        SecretKey passwordKey = UtilitatsXifrar.passwordKeyGeneration(password, 256);
        byte[] encryptedDataWithPassword = UtilitatsXifrar.encryptData(text.getBytes(), passwordKey);
        byte[] decryptedDataWithPassword = UtilitatsXifrar.decryptData(encryptedDataWithPassword, passwordKey);
        String decryptedTextWithPassword = new String(decryptedDataWithPassword);
        System.out.println("Text desxifrat amb clau generada amb passwordKeyGeneration: " + decryptedTextWithPassword);

        // ! 7. Prova alguns dels mètodes que proporciona la classe SecretKey
        System.out.println("\n────────────────────────────────────────────────────────────────────");
        System.out.println("  7. Prova alguns dels mètodes que proporciona la classe SecretKey");
        System.out.println("────────────────────────────────────────────────────────────────────");

        System.out.println("Algoritme de la clau: " + key.getAlgorithm());
        System.out.println("Format de la clau: " + key.getFormat());
        System.out.println("Bytes de la clau: " + Arrays.toString(key.getEncoded()));

        // ! 8. Desxifra el text del punt 6 i comprova que donant una paraula de pas incorrecte salta l'excepció BadPaddingException
        System.out.println("\n────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────");
        System.out.println("  8. Desxifra el text del punt 6 i comprova que donant una paraula de pas incorrecte salta l'excepció BadPaddingException");
        System.out.println("────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────");

        String wrongPassword = "contrasenyaIncorrecta";
        SecretKey wrongPasswordKey = UtilitatsXifrar.passwordKeyGeneration(wrongPassword, 256);
        try {
            byte[] decryptedDataWithWrongPassword = UtilitatsXifrar.decryptData(encryptedDataWithPassword, wrongPasswordKey);
            String decryptedTextWithWrongPassword = new String(decryptedDataWithWrongPassword);
            System.out.println("Text desxifrat amb clau generada amb contrasenya incorrecta: " + decryptedTextWithWrongPassword);
        } catch (javax.crypto.BadPaddingException ex) {
            System.out.println("Error al desxifrar amb contrasenya incorrecta: " + ex);
        } catch (Exception ex) {
            System.err.println("Error desconegut al desxifrar: " + ex);
        }

    }
}
