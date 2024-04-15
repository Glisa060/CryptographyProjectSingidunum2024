/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */
package rs.ac.singidunum.cryptographyproject2024;

/**
 *
 * @author Milan
 */
public class CryptographyProject2024 {

    public static void main(String[] args) {
        new Thread(() -> {
            try {
                Server.main(new String[]{});
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        try {
            Thread.sleep(1000); // Delay to ensure server starts before client
        } catch (InterruptedException e) {
        }

        new Thread(() -> {
            try {
                Client.main(new String[]{});
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
}
