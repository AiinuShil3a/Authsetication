package com.servlets;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.mindrot.jbcrypt.BCrypt;
import com.utility.DatabaseUtil;

public class UserManager {
    private DatabaseManager databaseManager;

    public UserManager() {
        this.databaseManager = new DatabaseManager();
    }

    public String getPasswordByUsername(String username) {
        return databaseManager.getPasswordByUsername(username);
    }

    public boolean checkPassword(String plainPassword, String storedHashedPassword) {
        return BCrypt.checkpw(plainPassword, storedHashedPassword);
    }
}

class RegisterManager {
    private DatabaseManager databaseManager;

    public RegisterManager() {
        this.databaseManager = new DatabaseManager();
    }

    public boolean isUsernameTaken(String username) {
        return databaseManager.isUsernameTaken(username);
    }

    public void registerUser(String username, String password) {
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
        databaseManager.insertUser(username, hashedPassword);
    }
}

class DatabaseManager {
    public boolean isUsernameTaken(String username) {
        String query = "SELECT COUNT(*) FROM Users WHERE username = ?";
        try (Connection conn = DatabaseUtil.getConnection();
             PreparedStatement stmt = conn.prepareStatement(query)) {

            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0; // ถ้ามีจำนวนมากกว่า 0 แสดงว่ามี username ซ้ำ
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public void insertUser(String username, String hashedPassword) {
        try (Connection conn = DatabaseUtil.getConnection()) {
            String query = "INSERT INTO Users (username, password) VALUES (?, ?)";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, username);
                stmt.setString(2, hashedPassword);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public String getPasswordByUsername(String username) {
        String storedHashedPassword = null;

        try (Connection conn = DatabaseUtil.getConnection()) {
            String query = "SELECT password FROM Users WHERE username = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, username);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    storedHashedPassword = rs.getString("password");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return storedHashedPassword;
    }
}
