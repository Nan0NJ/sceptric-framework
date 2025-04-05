package backend;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DBConn {
    private static final String DB_URL = "jdbc:sqlite:db/results_database/performance.db";
    private Connection connection;

    // Constructor to initialize connection
    public DBConn() throws SQLException {
        connection = DriverManager.getConnection(DB_URL);
        System.out.println("Connected to SQLite database.");
    }

    // Create tables
    public void createTables() throws SQLException {
        String createRawDataTable = "CREATE TABLE IF NOT EXISTS cryptographic_iterations (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "algorithm TEXT NOT NULL," +
                "iteration INTEGER NOT NULL," +
                "execution_time BIGINT NOT NULL," +
                "cpu_load REAL NOT NULL," +
                "memory_used BIGINT NOT NULL," +
                "cpu_power REAL NOT NULL," +
                "energy_consumption REAL NOT NULL," +
                "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP" +
                ");";

        String createSummaryTable = "CREATE TABLE IF NOT EXISTS algorithm_performance_summary (" +
                "algorithm TEXT PRIMARY KEY," +
                "avg_execution_time BIGINT NOT NULL," +
                "min_execution_time BIGINT NOT NULL," +
                "max_execution_time BIGINT NOT NULL," +
                "avg_cpu_load REAL NOT NULL," +
                "min_cpu_load REAL NOT NULL," +
                "max_cpu_load REAL NOT NULL," +
                "avg_memory_used BIGINT NOT NULL," +
                "min_memory_used BIGINT NOT NULL," +
                "max_memory_used BIGINT NOT NULL," +
                "avg_cpu_power REAL NOT NULL," +
                "min_cpu_power REAL NOT NULL," +
                "max_cpu_power REAL NOT NULL," +
                "avg_energy_consumption REAL NOT NULL," +
                "min_energy_consumption REAL NOT NULL," +
                "max_energy_consumption REAL NOT NULL," +
                "total_iterations INTEGER NOT NULL," +
                "test_date DATETIME NOT NULL" +
                ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createRawDataTable);
            stmt.execute(createSummaryTable);
            System.out.println("Tables created successfully.");
        }
    }

    // Drop tables (for resetting)
    public void dropTables() throws SQLException {
        String dropRawDataTable = "DROP TABLE IF EXISTS cryptographic_iterations;";
        String dropSummaryTable = "DROP TABLE IF EXISTS algorithm_performance_summary;";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(dropRawDataTable);
            stmt.execute(dropSummaryTable);
            System.out.println("Tables dropped successfully.");
        }
    }

    // Get connection for other operations
    public Connection getConnection() {
        return connection;
    }

    // Close connection
    public void close() throws SQLException {
        if (connection != null && !connection.isClosed()) {
            connection.close();
            System.out.println("Database connection closed.");
        }
    }

    public void resetTables() throws SQLException {
        dropTables();
        createTables();
    }

    public static void main(String[] args) {
        try {
            DBConn dbConn = new DBConn();
            dbConn.resetTables();
            dbConn.close();
            System.out.println("Database tables have been reset and created successfully.");
        } catch (SQLException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}