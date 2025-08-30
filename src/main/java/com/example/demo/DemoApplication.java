package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.sql.*;

@SpringBootApplication
@RestController
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @GetMapping("/")
    public String hello() {
        return "Hello from Spring Boot on Kubernetes!";
    }

    // ===== Vulnerable endpoint: SQL Injection =====
    // Example: http://localhost:8080/user?username=admin' OR '1'='1
    @GetMapping("/user")
    public String getUser(@RequestParam String username) throws Exception {
        String url = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1";
        try (Connection conn = DriverManager.getConnection(url, "sa", "");
             Statement stmt = conn.createStatement()) {

            stmt.execute("CREATE TABLE IF NOT EXISTS users(id INT PRIMARY KEY, username VARCHAR(255));");
            stmt.execute("INSERT INTO users VALUES (1, 'admin');");

            // BAD: untrusted input concatenated directly into SQL query
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            System.out.println("Running query: " + query);

            try (ResultSet rs = stmt.executeQuery(query)) {
                if (rs.next()) {
                    return "User found: " + rs.getString("username");
                }
            }
        }
        return "No user found";
    }

    // ===== Vulnerable endpoint: Command Injection =====
    // Example: http://localhost:8080/run?cmd=ls
    @GetMapping("/run")
    public String runCommand(@RequestParam String cmd) throws Exception {
        // BAD: user input directly passed to system shell
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        }
    }
}
