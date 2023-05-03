import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DesxifrarMissatge {
    public static void main(String[] args) {
        try {
            // ? Leer el texto cifrado
            Path path = Paths.get("src/textamagat.crypt");
            byte[] textXifrat = Files.readAllBytes(path);

            // ? Leer todas las contraseñas
            File contrasenyesFile = new File("src/clausA4.txt");
            FileReader fr = new FileReader(contrasenyesFile);
            BufferedReader br = new BufferedReader(fr);

            // ? Probar cada contraseña hasta encontrar la correcta
            String contrasenya;
            boolean trobat = false;
            while ((contrasenya = br.readLine()) != null && !trobat) {
                SecretKey key = UtilitatsXifrar.passwordKeyGeneration(contrasenya, 256);
                try {
                    byte[] textDesxifrat = UtilitatsXifrar.decryptData(textXifrat, key);
                    String missatgeDesxifrat = new String(textDesxifrat, "UTF-8");
                    System.out.println("Missatge desxifrat amb contrasenya: " + contrasenya);
                    System.out.println("Missatge: " + missatgeDesxifrat);
                    trobat = true;
                } catch (javax.crypto.BadPaddingException ex) {
                    System.out.println("Contrasenya incorrecta: " + contrasenya);
                }
            }
            if (!trobat) {
                System.out.println("No s'ha trobat la contrasenya correcta.");
            }
            br.close();
        } catch (Exception ex) {
            System.err.println("Error: " + ex);
        }
    }
}
