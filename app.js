const express = require("express");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const CookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const app = express();
dotenv.config({ path: "./.env" });

app.use(bodyParser.json()); // Parses JSON bodies
app.use(express.json());
app.use(CookieParser());

// CORS settings
app.use(
  cors({
    origin: "http://localhost:5173", // Frontend address
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true, // Allow credentials (cookies)
  })
);

// Connect to the database (promise-based connection)
let db;

(async () => {
  try {
    db = await mysql.createConnection({
      host: process.env.DATABASE_HOST,
      user: process.env.DATABASE_USER,
      password: process.env.DATABASE_PASSWORD,
      database: process.env.DATABASE,
    });
    console.log("Database Connected");
  } catch (error) {
    console.error("Database connection failed:", error.message);
  }
})();

// Middleware to verify the JWT token
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ Status: "Error", Message: "Unauthorized" });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .json({ Status: "Error", Message: "Invalid token" });
    }
    req.user = decoded; // Attach user information from the token
    next();
  });
};

const create_date = new Date().toISOString().slice(0, 19).replace("T", " "); // Format as 'YYYY-MM-DD HH:MM:SS'

// Endpoint to check if the user is authenticated
app.get("/check-session", verifyUser, (req, res) => {
  return res.status(200).json({ Status: "Success", User: req.user });
});

// Login endpoint
app.post("/login", (req, res) => {
  const emailFromRequest = req.body.email.trim();
  const passwordFromRequest = req.body.password.trim();

  // Query the database to find the user by email
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [emailFromRequest], (err, data) => {
    if (err) {
      return res.json({ Error: "Login Error in server" });
    }

    if (data.length > 0) {
      const user = data[0]; // User data from the database

      // Compare passwords directly (you should hash passwords in production)
      if (String(user.password).trim() === String(passwordFromRequest).trim()) {
        const token = jwt.sign(
          { email: user.email, nama: user.nama },
          process.env.SECRET_KEY,
          {
            // Include 'nama' in the token payload
            expiresIn: "2h",
          }
        );

        // Set the token in the cookies
        res.cookie("token", token, {
          httpOnly: true,
          secure: false, // Set to true in production
        });

        return res.json({
          Success: "Login successful",
          Token: token,
          User: {
            email: user.email,
            nama: user.nama, // Include 'nama' in the response
          },
        });
      } else {
        return res.json({ Error: "Incorrect password" });
      }
    } else {
      return res.json({ Error: "No user found for the given email" });
    }
  });
});

// Logout endpoint
app.post("/logout", (req, res) => {
  // Clear the token cookie
  res.clearCookie("token", { httpOnly: true, secure: false });
  res.json({ Status: "Success", Message: "Logged out successfully" });
});
// Create a new product
app.post("/produk-sampah", verifyUser, (req, res) => {
  const { category_id, uom_id, list_price, cost_price, image } = req.body;

  if (!category_id || !uom_id || !list_price || !cost_price) {
    return res.status(400).json({ Error: "Required fields are missing" });
  }

  // Automatically get the 'created_by' and 'updated_by' from the logged-in user
  const createdBy = req.user.id; // Assuming the user ID is in the decoded JWT token
  const updatedBy = req.user.id; // Same here, you can use the same user for updates

  // Set a default name if not provided
  const name = `Product ${category_id}`; // You can adjust this as needed to generate a name

  // SQL query to insert new data
  const sql = `
    INSERT INTO product_product (category_id, uom_id, created_by, updated_by, name, list_price, cost_price, image, create_date, write_date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`;

  const values = [
    category_id,
    uom_id,
    createdBy,
    updatedBy,
    name,
    list_price,
    cost_price,
    image,
  ];

  db.query(sql, values, (err, result) => {
    if (err) {
      return res
        .status(500)
        .json({ Error: "Error inserting data", Details: err.message });
    }
    return res.status(201).json({
      Success: "Product added successfully",
      InsertedID: result.insertId,
    });
  });
});

// Update product by ID
app.put("/produk-sampah/:id", verifyUser, (req, res) => {
  const { id } = req.params; // Get the product ID from the request parameters
  const { category_id, uom_id, list_price, cost_price, image } = req.body;

  if (!category_id || !uom_id || !list_price || !cost_price) {
    return res.status(400).json({ Error: "Required fields are missing" });
  }

  // Automatically get the 'updated_by' from the logged-in user
  const updatedBy = req.user.id; // Assuming the user ID is in the decoded JWT token

  // Set a default name based on the category_id (or fetch an existing name from the DB)
  const name = `Updated Product ${category_id}`;

  // SQL query to update the data
  const sql = `
    UPDATE product_product 
    SET category_id = ?, uom_id = ?, updated_by = ?, name = ?, list_price = ?, cost_price = ?, image = ?, write_date = NOW()
    WHERE id = ?`;

  const values = [
    category_id,
    uom_id,
    updatedBy,
    name,
    list_price,
    cost_price,
    image,
    id,
  ];

  db.query(sql, values, (err, result) => {
    if (err) {
      return res
        .status(500)
        .json({ Error: "Error updating data", Details: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ Error: "No record found with this ID" });
    }
    return res.json({ Success: "Product updated successfully" });
  });
});

// API for creating a new user

// API for creating a new user with password hashing
app.post("/api/users", async (req, res) => {
  const { email, password, name, total_points = 0, active = true } = req.body;

  // Basic validation for required fields
  if (!email || !password || !name) {
    return res.status(400).json({
      message: "Email, password, and name are required.",
    });
  }

  try {
    // Hash the password using bcrypt before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

    // SQL query to insert a new user with hashed password
    const query = `
      INSERT INTO res_users (email, password, name, total_points, active)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.query(
      query,
      [email, hashedPassword, name, total_points, active],
      (err, result) => {
        if (err) {
          console.error("Error inserting new user:", err);
          return res.status(500).json({ message: "Failed to create user" });
        }

        // Return the newly created user data (without the password)
        res.status(201).json({
          id: result.insertId,
          email,
          name,
          total_points,
          active,
        });
      }
    );
  } catch (error) {
    console.error("Error hashing password:", error);
    res.status(500).json({ message: "Error processing the password" });
  }
});

//get user
app.get("/api/users", (req, res) => {
  db.query("SELECT * FROM res_users", (err, result) => {
    if (err) {
      return res
        .status(500)
        .json({ message: "Failed to fetch users", error: err });
    }
    console.log(result); // Debugging: View all users
    res.status(200).json(result);
  });
});

app.delete("/api/users/:id", (req, res) => {
  const { id } = req.params;

  // Check if the user ID is provided
  if (!id) {
    return res.status(400).json({
      message: "User ID is required.",
    });
  }

  // Log the attempt to delete the user
  console.log(`Attempting to delete user with ID: ${id}`);

  // SQL query to delete the user based on the ID
  const query = `DELETE FROM res_users WHERE id = ?`;

  // Execute the query
  db.query(query, [id], (err, result) => {
    if (err) {
      // Log detailed error if the query fails
      console.error("Error deleting user:", err);
      return res
        .status(500)
        .json({ message: "Failed to delete user", error: err.message });
    }

    // Check if any row was deleted (affectedRows will be 0 if no user was found)
    if (result.affectedRows === 0) {
      console.log(`User with ID: ${id} not found.`);
      return res.status(404).json({ message: "User not found" });
    }

    // Log success message if the user is deleted
    console.log(`User with ID: ${id} deleted successfully`);
    return res.status(200).json({ message: "User deleted successfully" });
  });
});

// API for updating a user
app.put("/api/users/:id", async (req, res) => {
  const { id } = req.params;
  const { email, password, name, total_points, active } = req.body;

  // Basic validation for required fields
  if (!email || !name) {
    return res.status(400).json({
      message: "Email and name are required.",
    });
  }

  try {
    // Hash the new password if provided
    let hashedPassword = password ? await bcrypt.hash(password, 10) : undefined;

    // SQL query to update the user
    const query = `
      UPDATE res_users
      SET email = ?, name = ?, total_points = ?, active = ?, password = COALESCE(?, password)
      WHERE id = ?
    `;

    db.query(
      query,
      [email, name, total_points || 0, active || true, hashedPassword, id],
      (err, result) => {
        if (err) {
          console.error("Error updating user:", err);
          return res.status(500).json({ message: "Failed to update user" });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({
          message: "User updated successfully",
          id,
          email,
          name,
          total_points: total_points || 0,
          active: active || true,
        });
      }
    );
  } catch (error) {
    console.error("Error processing the password:", error);
    res.status(500).json({ message: "Error processing the password" });
  }
});

//UOM
//get
app.get("/uom", (req, res) => {
  const query = "SELECT * FROM uom_uom";

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching UOMs:", err);
      return res.status(500).json({ error: "Failed to retrieve UOMs" });
    }
    res.status(200).json({ uoms: results });
  });
});

//post
app.post("/uom", async (req, res) => {
  const { name, factor } = req.body;

  if (!name || !factor) {
    return res.status(400).json({ message: "Name and factor are required." });
  }

  const category_id = 1; // Default category_id
  const created_by = 1; // Example user ID
  const create_date = new Date().toISOString().slice(0, 19).replace("T", " "); // Convert to 'YYYY-MM-DD HH:MM:SS'

  try {
    const query = `
      INSERT INTO uom_uom (category_id, created_by, name, factor, create_date)
      VALUES (?, ?, ?, ?, ?)
    `;

    const [result] = await db.query(query, [
      category_id,
      created_by,
      name,
      factor,
      create_date,
    ]);

    res.status(201).json({
      message: "UOM added successfully",
      id: result.insertId,
    });
  } catch (error) {
    console.error("Error details:", error); // Log detailed error
    res.status(500).json({
      message: "Error adding UOM",
      error: error.message,
    });
  }
});

// DELETE UOM by ID
// Create a regular connection or pool (non-promise)

app.delete("/uom/:id", (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({
      message: "UOM ID is required.",
    });
  }

  const query = `DELETE FROM uom_uom WHERE id = ?`;

  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Error deleting UOM:", err);
      return res.status(500).json({
        message: "Failed to delete UOM",
        error: err.message,
      });
    }

    if (result.affectedRows === 0) {
      console.log(`UOM with ID: ${id} not found.`);
      return res.status(404).json({ message: "UOM not found" });
    }

    console.log(`UOM with ID: ${id} deleted successfully`);
    return res.status(200).json({ message: "UOM deleted successfully" });
  });
});

// EDIT UOM by ID (PUT)
app.put("/uom/:id", async (req, res) => {
  const { id } = req.params;
  const { name, factor, category_id, created_by } = req.body;

  // Validate required fields
  if (!name || !factor) {
    return res.status(400).json({ message: "Name and factor are required." });
  }

  try {
    // SQL Query to update the UOM
    const query = `
      UPDATE uom_uom 
      SET 
        name = ?, 
        factor = ?, 
        category_id = ?, 
        created_by = ? 
      WHERE id = ?
    `;

    // Execute the query using async/await
    const [result] = await db.query(query, [
      name,
      factor,
      category_id || null, // Default to NULL if not provided
      created_by || null, // Default to NULL if not provided
      id,
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "UOM not found" });
    }

    res.status(200).json({ message: "UOM updated successfully" });
  } catch (error) {
    console.error("Error updating UOM:", error);
    res
      .status(500)
      .json({ message: "Error updating UOM", error: error.message });
  }
});

// Start the server
app.listen(process.env.PORT, () => {
  console.log("Server is running on port " + process.env.PORT);
});
