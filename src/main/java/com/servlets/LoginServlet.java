package com.servlets;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;

import com.utility.DatabaseUtil;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

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

        if (storedHashedPassword == null) {
            response.sendRedirect("login.html?error=user_not_found");
        } else if (BCrypt.checkpw(password, storedHashedPassword)) {
            response.sendRedirect("dashboard.html");
        } else {
            response.sendRedirect("login.html?error=incorrect_password");
        }
    }
}

