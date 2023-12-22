package org.example;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.*;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.sql.*;
import java.time.Instant;

public class Serveur {
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;

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
                    System.out.println("Reception username");
                    String hashedPassword = getHashedPassword(username);
                    dataOutputStream.writeUTF(hashedPassword);

                    String requestType = dataInputStream.readUTF();
                    String baseDirectory = dataInputStream.readUTF();

                    if (requestType.equals("RESTORE")) {
                        sendFilesToClient(username, baseDirectory);
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

    private static Connection connectToDB() throws SQLException {
        String url = "jdbc:sqlite:users.db"; // Chemin vers votre base de données SQLite
        return DriverManager.getConnection(url);
    }

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

    private static void receiveFiles(String clientName) throws IOException {
        File clientDir = new File(clientName);
        if (!clientDir.exists()) {
            clientDir.mkdirs();
        }
        String relativePath = dataInputStream.readUTF();
        while (!relativePath.equals("END")) {

            File destinationFile = new File(clientDir, relativePath);
            long fileSize = dataInputStream.readLong();
            if (!destinationFile.exists() || destinationFile.length() != fileSize) {
                receiveFile(destinationFile, fileSize);
            }
            relativePath = dataInputStream.readUTF();
        }
    }

    private static void receiveFile(File file, long fileSize) throws IOException {
        file.getParentFile().mkdirs();

        try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            byte[] buffer = new byte[4 * 1024];
            int bytes;
            while (fileSize > 0) {
                int encryptedDataLength = dataInputStream.readInt();
                if (encryptedDataLength > buffer.length) {
                    buffer = new byte[encryptedDataLength];
                }
                dataInputStream.readFully(buffer, 0, encryptedDataLength);
                fileOutputStream.write(buffer, 0, encryptedDataLength);
                fileSize -= encryptedDataLength;
            }
        }
        System.out.println("File " + file.getName() + " received and saved.");
    }

    private static void sendFilesToClient(String clientName, String restorePath) throws IOException {
        Path clientDir = Paths.get(clientName);
        if (Files.exists(clientDir)) {
            Files.walk(clientDir)
                    .filter(Files::isRegularFile)
                    .forEach(file -> {
                        try {
                            byte[] fileData = Files.readAllBytes(file);

                            String relativePath = clientDir.relativize(file).toString();
                            dataOutputStream.writeUTF(relativePath);
                            dataOutputStream.writeInt(fileData.length);
                            dataOutputStream.write(fileData);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });
            dataOutputStream.writeUTF("END");
        } else {
            dataOutputStream.writeUTF("END");
            System.out.println("No files to restore for client: " + clientName);
        }
    }

    private static void sendLastBackupTimeToClient(String username) throws IOException {
        try {
            Instant lastBackupTime = readLastBackupTimeFromDB(username);
            dataOutputStream.writeUTF(lastBackupTime.toString());
        } catch (SQLException e) {
            e.printStackTrace();
            dataOutputStream.writeUTF(Instant.MIN.toString()); // Envoie une date par défaut en cas d'erreur
        }
    }

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
