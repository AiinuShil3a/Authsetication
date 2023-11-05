package com.servlets;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/register")
public class RegisterServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        RegisterManager registerManager = new RegisterManager();
        if (registerManager.isUsernameTaken(username)) {
            response.sendRedirect("register.html?error=username_taken");
            return;
        }

        registerManager.registerUser(username, password);
        response.sendRedirect("login.html");
    }
}
