package org.example;
import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import java.security.GeneralSecurityException;
import java.sql.*;
import java.time.Instant;

public class Serveur {
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;
    private static SecretKey  secretKey;

    public static void main(String[] args) throws IOException {
        String keystore = "mykeystore.jks";
        String keystorePassword = "app_sauvegarde";

        System.setProperty("javax.net.ssl.keyStore", keystore);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePassword);

        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        try (SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(6666)) {
            System.out.println("Server is Starting in Port 6666");

            while (true) { // Boucle pour accepter plusieurs connexions/plusieurs fichiers
                try (Socket clientSocket = serverSocket.accept();) {
                    System.out.println("Connected to a client");
                    dataInputStream = new DataInputStream(clientSocket.getInputStream());
                    dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

                    String username = dataInputStream.readUTF();
                    String password = dataInputStream.readUTF();
                    String hashedPassword = getHashedPassword(username);
                    secretKey = HashingPassword.stringToKey(hashedPassword, "AES");
                    assert hashedPassword != null;
                    boolean isAuthentificated = HashingPassword.validatePassword(password, hashedPassword, HashingPassword.decodeSalt(getSalt(username)),1000);

                    if(isAuthentificated) {
                        dataOutputStream.writeUTF("Connecté");
                    }
                    else {
                        dataOutputStream.writeUTF("Non Connecté");
                    }

                    String requestType = dataInputStream.readUTF();
                    String baseDirectory = dataInputStream.readUTF();

                    if (requestType.equals("RESTORE")) {
                        sendFilesToClient(username, baseDirectory, HashingPassword.stringToKey(hashedPassword, "AES"));
                    } else {
                        sendLastBackupTimeToClient(username);
                        receiveFiles(username);
                        updateLastBackupTimeInDB(username);
                    }

                    dataInputStream.close();
                    dataOutputStream.close();
                    clientSocket.close();
                } catch (IOException e) {
                    System.err.println("Error handling client connection: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Effectue la connection à la base de donnée
     * @return
     * @throws SQLException
     */
    private static Connection connectToDB() throws SQLException {
        String url = "jdbc:sqlite:users.db"; // Chemin vers votre base de données SQLite
        return DriverManager.getConnection(url);
    }

    /**
     * Récupère le mot de passe hashé de la base de donnée
     * @param username
     * @return
     */
    private static String getHashedPassword(String username) {
        try (Connection conn = connectToDB();
             PreparedStatement pstmt = conn.prepareStatement("SELECT password FROM users WHERE username = ?")) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedPassword = rs.getString("password");
                return storedPassword;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Récupère le sel de la base de données
     * @param username
     * @return
     */
    private static String getSalt(String username) {
        try (Connection conn = connectToDB();
             PreparedStatement pstmt = conn.prepareStatement("SELECT salt FROM users WHERE username = ?")) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String salt = rs.getString("salt");
                return salt;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Gère la réception et l'enregistrement des fichiers envoyés par des clients
     * @param clientName
     * @throws IOException
     */
    private static void receiveFiles(String clientName) throws IOException {
        File clientDir = new File(clientName);
        if (!clientDir.exists()) {
            clientDir.mkdirs();
        }
        String relativePath = dataInputStream.readUTF();
        while (!relativePath.equals("END")) {
            long fileSize = dataInputStream.readLong();
            File destinationFile = new File(clientDir, relativePath);
            System.out.println("Chemin du fichier sur le serveur: " + destinationFile.getAbsolutePath());

            receiveAndEncryptFile(destinationFile, fileSize);
            relativePath = dataInputStream.readUTF();
        }
    }

    /**
     * Gère le chiffrement des données reçus
     * @param file
     * @param fileSize
     * @throws IOException
     */
    private static void receiveAndEncryptFile(File file, long fileSize) throws IOException {
        // Créer les dossiers parents s'ils n'existent pas
        File parentDir = file.getParentFile();
        if (!parentDir.exists()) {
            parentDir.mkdirs();
        }

        // Créer le fichier s'il n'existe pas
        if (!file.exists()) {
            file.createNewFile();
        }

        // Continuer avec la réception et le chiffrement du fichier
        byte[] buffer = new byte[4 * 1024];
        int bytes;
        ByteArrayOutputStream fileContent = new ByteArrayOutputStream();

        while (fileSize > 0 && (bytes = dataInputStream.read(buffer, 0, Math.min(buffer.length, (int) fileSize))) != -1) {
            fileContent.write(buffer, 0, bytes);
            fileSize -= bytes;
        }

        byte[] encryptedData = encryptData(fileContent.toByteArray(), secretKey);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(encryptedData);
        }
    }

    /**
     * Gère le chiffrements des datas
     * @param data
     * @param key
     * @return
     */
    private static byte[] encryptData(byte[] data, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Gère de le déchiffrements des données
     * @param data
     * @param key
     * @return
     * @throws GeneralSecurityException
     */
    private static byte[] decryptData(byte[] data, SecretKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * Envoie les fichiers de chaque client lors d'une restauration
     * @param clientName
     * @param restorePath
     * @param key
     * @throws IOException
     */
    private static void sendFilesToClient(String clientName, String restorePath, SecretKey key) throws IOException {
        Path clientDir = Paths.get(clientName);
        if (Files.exists(clientDir)) {
            Files.walk(clientDir)
                    .filter(Files::isRegularFile)
                    .forEach(file -> {
                        try {
                            // Lire et déchiffrer le fichier
                            byte[] fileData = Files.readAllBytes(file);
                            byte[] decryptedData = decryptData(fileData, key);

                            // Envoyer le nom du fichier et les données déchiffrées
                            String relativePath = clientDir.relativize(file).toString();
                            dataOutputStream.writeUTF(relativePath); // Envoyer d'abord le nom
                            dataOutputStream.writeLong(decryptedData.length); // Puis la taille
                            dataOutputStream.write(decryptedData); // Enfin les données
                        } catch (IOException | GeneralSecurityException e) {
                            System.err.println("Erreur lors de l'envoi du fichier: " + file);
                            e.printStackTrace();
                        }
                    });
            dataOutputStream.writeUTF("END");
        } else {
            dataOutputStream.writeUTF("END");
            System.out.println("Aucun fichier à restaurer pour le client: " + clientName);
        }
    }

    /**
     * Envoie la date de dernière sauvegarde au client
     * @param username
     * @throws IOException
     */
    private static void sendLastBackupTimeToClient(String username) throws IOException {
        try {
            Instant lastBackupTime = readLastBackupTimeFromDB(username);
            dataOutputStream.writeUTF(lastBackupTime.toString());
        } catch (SQLException e) {
            e.printStackTrace();
            dataOutputStream.writeUTF(Instant.MIN.toString()); // Envoie une date par défaut en cas d'erreur
        }
    }

    /**
     * Récupère la date de dernière sauvegarde dans la base de données
     * @param username
     * @return
     * @throws SQLException
     */
    private static Instant readLastBackupTimeFromDB(String username) throws SQLException {
        try (Connection conn = connectToDB();
             PreparedStatement pstmt = conn.prepareStatement("SELECT last_backup FROM users WHERE username = ?")) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String lastBackupString = rs.getString("last_backup");
                if (lastBackupString != null && !lastBackupString.isEmpty()) {
                    return Instant.parse(lastBackupString); // Convertir la chaîne de texte en Instant
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return Instant.MIN; // Si aucune donnée n'est trouvée ou en cas d'erreur, retourne une date très
        // ancienne
    }

    /**
     * Mets à jour la date de dernière sauvegarde dans la base de données
     * @param username
     * @throws SQLException
     */
    private static void updateLastBackupTimeInDB(String username) throws SQLException {
        try (Connection conn = connectToDB();
             PreparedStatement pstmt = conn
                     .prepareStatement("UPDATE users SET last_backup = ? WHERE username = ?")) {
            pstmt.setString(1, Instant.now().toString());
            pstmt.setString(2, username);
            pstmt.executeUpdate();
        }
    }

}
