package com.servlets;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        UserManager userManager = new UserManager();
        String storedHashedPassword = userManager.getPasswordByUsername(username);

        if (storedHashedPassword == null) {
            response.sendRedirect("login.html?error=user_not_found");
        } else if (userManager.checkPassword(password, storedHashedPassword)) {
            response.sendRedirect("dashboard.html");
        } else {
            response.sendRedirect("login.html?error=incorrect_password");
        }
    }
}
