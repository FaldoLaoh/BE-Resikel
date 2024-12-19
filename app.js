const express = require("express");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const CookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const app = express();
const multer = require("multer");
const path = require("path");
dotenv.config({ path: "./.env" });
const fs = require("fs");

// Ensure the uploads directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log("Uploads directory created");
}

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

// Fetch all UOMs
app.get("/uom/byId", (req, res) => {
  const query = "SELECT id, name FROM db_resikel.uom_uom";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching UOMs: ", err.message);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json(results);
  });
});

// Get All Categories
app.get("/api/categories", (req, res) => {
  const sql = "SELECT * FROM product_category";
  db.query(sql, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Failed to fetch categories" });
    }
    res.json(results);
  });
});

//name by id category

// Get Category by ID
app.get("/api/categories/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM product_category WHERE id = ?";
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Failed to fetch the category" });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.json(results[0]);
  });
});

// Create a New Category
app.post("/api/categories", (req, res) => {
  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ message: "Category name is required" });
  }
  const sql = "INSERT INTO product_category (name) VALUES (?)";
  db.query(sql, [name], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Failed to create the category" });
    }
    res.status(201).json({ id: results.insertId, name });
  });
});

// Update a Category
app.put("/api/categories/:id", (req, res) => {
  const { id } = req.params;
  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ message: "Category name is required" });
  }
  const sql = "UPDATE product_category SET name = ? WHERE id = ?";
  db.query(sql, [name, id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Failed to update the category" });
    }
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.json({ id, name });
  });
});

// Delete a Category
app.delete("/api/categories/:id", (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM product_category WHERE id = ?";
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Failed to delete the category" });
    }
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.json({ message: "Category deleted successfully" });
  });
});

app.get("/api/categories/byId", (req, res) => {
  const query = "SELECT id, name FROM db_resikel.product_category";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching categories: ", err.message);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json(results);
  });
});
//Product

// API Endpoint: Fetch all products
// app.get("/api/products", (req, res) => {
//   const query = `
//     SELECT
//       product_product.id,
//       product_product.category_id,
//       product_product.uom_id,
//       product_product.created_by,
//       product_product.updated_by,
//       product_product.name,
//       product_product.list_price,
//       product_product.cost_price,
//       product_product.image,
//       product_product.create_date,
//       product_product.write_date
//     FROM db_resikel.product_product;
//   `;

//   db.query(query, (err, results) => {
//     if (err) {
//       console.error("Error fetching products: ", err.message);
//       return res.status(500).json({ error: "Internal Server Error" });
//     }
//     res.json(results);
//   });
// });

// API Endpoint: Fetch all products
app.get("/api/products", (req, res) => {
  const query = `
    SELECT 
      pp.id, 
      pp.name, 
      pp.list_price, 
      pp.cost_price, 
      pp.category_id, 
      pc.name AS category_name,  -- Category Name
      pp.uom_id, 
      u.name AS uom_name,       -- UOM Name
      pp.created_by, 
      pp.updated_by, 
      pp.create_date, 
      pp.write_date 
    FROM db_resikel.product_product pp
    LEFT JOIN db_resikel.product_category pc ON pp.category_id = pc.id
    LEFT JOIN db_resikel.uom_uom u ON pp.uom_id = u.id;
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching products: ", err.message);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json(results);
  });
});

// Create new product
app.post("/api/products", (req, res) => {
  const { name, category_id, uom_id, list_price, cost_price } = req.body;
  const query = `
    INSERT INTO db_resikel.product_product (name, category_id, uom_id, list_price, cost_price)
    VALUES (?, ?, ?, ?, ?)
  `;
  db.query(
    query,
    [name, category_id, uom_id, list_price, cost_price],
    (err, result) => {
      if (err) {
        console.error("Error creating product: ", err.message);
        return res.status(500).json({ error: "Internal Server Error" });
      }
      res.status(201).json({ message: "Product created successfully" });
    }
  );
});

// Update existing product
app.put("/api/products/:id", (req, res) => {
  const { id } = req.params;
  const { name, category_id, uom_id, list_price, cost_price } = req.body;
  const query = `
    UPDATE db_resikel.product_product
    SET name = ?, category_id = ?, uom_id = ?, list_price = ?, cost_price = ?
    WHERE id = ?
  `;
  db.query(
    query,
    [name, category_id, uom_id, list_price, cost_price, id],
    (err, result) => {
      if (err) {
        console.error("Error updating product: ", err.message);
        return res.status(500).json({ error: "Internal Server Error" });
      }
      res.status(200).json({ message: "Product updated successfully" });
    }
  );
});

// DELETE: Remove a product
app.delete("/api/products/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM db_resikel.product_product WHERE id=?;";
  db.query(query, [id], (err) => {
    if (err) {
      console.error("Error deleting product: ", err.message);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json({ message: "Product deleted successfully" });
  });
});

// Endpoint to get aggregate statistics for the dashboard
app.get("/api/dashboard/stats", (req, res) => {
  const userCountQuery = `
    SELECT 
      COUNT(*) AS user_count,
      SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) AS active_user_count,
      SUM(CASE WHEN active = 0 THEN 1 ELSE 0 END) AS inactive_user_count
    FROM res_users
  `;
  const productCountQuery =
    "SELECT COUNT(*) AS product_count FROM product_product";
  const uomCountQuery = "SELECT COUNT(*) AS uom_count FROM uom_uom";
  const postCountQuery = " SELECT COUNT(*) AS post_post";

  db.query(userCountQuery, (err, userResult) => {
    if (err)
      return res
        .status(500)
        .json({ Error: "Failed to fetch user count", Details: err.message });
    db.query(productCountQuery, (err, productResult) => {
      if (err)
        return res.status(500).json({
          Error: "Failed to fetch product count",
          Details: err.message,
        });
      db.query(uomCountQuery, (err, uomResult) => {
        if (err)
          return res
            .status(500)
            .json({ Error: "Failed to fetch UOM count", Details: err.message });
        db.query(postCountQuery, (err, resultPost) => {
          if (err)
            return res.status(500).json({
              Error: "Failed to fetch post count",
              Details: err.message,
            });
        });
        // Return the aggregated data
        return res.json({
          user_count: userResult[0].user_count,
          active_user_count: userResult[0].active_user_count,
          inactive_user_count: userResult[0].inactive_user_count,
          product_count: productResult[0].product_count,
          uom_count: uomResult[0].uom_count,
          // post_count: resultPost[0].post_count, // <-- resultPost is undefined here
        });
      });
    });
  });
});

// Create a new category
app.post("/api/post_category", (req, res) => {
  const { name } = req.body;
  const query = "INSERT INTO post_category (name) VALUES (?)";

  db.query(query, [name], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ message: "Category created", id: result.insertId });
  });
});

// Get all categories
app.get("/api/post_category", (req, res) => {
  const query = "SELECT * FROM post_category";

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(result);
  });
});

// Update a category
app.put("/api/post_category/:id", (req, res) => {
  const { id } = req.params;
  const { name } = req.body;
  const query = "UPDATE post_category SET name = ? WHERE id = ?";

  db.query(query, [name, id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.json({ message: "Category updated" });
  });
});

// Delete a category
app.delete("/api/post_category/:id", (req, res) => {
  const { id } = req.params;
  const query = "DELETE FROM post_category WHERE id = ?";

  db.query(query, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.json({ message: "Category deleted" });
  });
});

// -------- CRUD for Post (Article) --------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = "uploads/";
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});

// Initialize multer with file size limit (optional)
const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // File size limit of 10MB
  fileFilter: (req, file, cb) => {
    // Only allow image files
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("File is not an image"), false); // Reject non-image files
    }
  },
});

app.get("/api/post_post", (req, res) => {
  const query = "SELECT * FROM post_post";

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json(result); // Send all posts in the response
  });
});

app.get("/api/post_post/total", (req, res) => {
  const query = "SELECT COUNT(*) AS total_posts FROM post_post";

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    // Send the total post count in the response
    res.status(200).json({
      totalPosts: result[0].total_posts,
    });
  });
});

app.get("/api/post_post/kegiatan", (req, res) => {
  // Get 'page' and 'limit' query parameters, set defaults if not provided
  const page = parseInt(req.query.page) || 1; // Default to page 1
  const limit = parseInt(req.query.limit) || 4; // Default to 4 posts per page
  const offset = (page - 1) * limit; // Calculate the offset for the SQL query

  // Modify the query to include LIMIT and OFFSET for pagination
  const query = `
    SELECT * FROM post_post 
    WHERE category_id = 1
    LIMIT ? OFFSET ?
  `;

  db.query(query, [limit, offset], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "No posts found" });
    }

    // Respond with the posts and also include pagination information
    res.status(200).json({
      posts: result,
      currentPage: page,
      totalPages: Math.ceil(result.length / limit), // Calculate total pages
    });
  });
});

app.post("/api/post_post/artikel", upload.single("foto"), (req, res) => {
  // Check if the file is uploaded
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  // Extract other form fields from req.body
  const { user_id, category_id, title, description } = req.body;

  // Get the uploaded file's path or filename
  const foto = req.file ? req.file.filename : null;

  // Prepare the SQL query to insert the data into the database
  const query =
    "INSERT INTO post_post (user_id, category_id, title, foto, description) VALUES (?, 2, ?, ?, ?)";

  db.query(
    query,
    [user_id, category_id, title, foto, description],
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ message: "Post created", id: result.insertId });
    }
  );
});

app.get("/api/post_post/artikel", (req, res) => {
  // Get 'page' and 'limit' query parameters, set defaults if not provided
  const page = parseInt(req.query.page) || 1; // Default to page 1
  const limit = parseInt(req.query.limit) || 4; // Default to 4 posts per page
  const offset = (page - 1) * limit; // Calculate the offset for the SQL query

  // Modify the query to include LIMIT and OFFSET for pagination
  const query = `
    SELECT * FROM post_post 
    WHERE category_id = 2
    LIMIT ? OFFSET ?
  `;

  db.query(query, [limit, offset], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "No posts found" });
    }

    // Respond with the posts and also include pagination information
    res.status(200).json({
      posts: result,
      currentPage: page,
      totalPages: Math.ceil(result.length / limit), // Calculate total pages
    });
  });
});

app.get("/api/post_post/artikel/:id", (req, res) => {
  const { id } = req.params; // Extract the ID from the URL parameters

  const query = "SELECT * FROM post_post WHERE id = ? AND category_id = 2";

  db.query(query, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Post not found" });
    }

    res.status(200).json(result[0]); // Return the first post that matches the ID
  });
});

app.get("/api/post_post/kegiatan/:id", (req, res) => {
  const { id } = req.params; // Extract the ID from the URL parameters

  const query = "SELECT * FROM post_post WHERE id = ? AND category_id = 1";

  db.query(query, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Post not found" });
    }

    res.status(200).json(result[0]); // Return the first post that matches the ID
  });
});

// Create a new post
// app.post("/api/post_post", (req, res) => {
//   const { user_id, category_id, title, foto, description } = req.body;
//   const query =
//     "INSERT INTO post_post (user_id, category_id, title, foto, description) VALUES (?, ?, ?, ?, ?)";

//   db.query(
//     query,
//     [user_id, category_id, title, foto, description],
//     (err, result) => {
//       if (err) {
//         return res.status(500).json({ error: err.message });
//       }
//       res.status(201).json({ message: "Post created", id: result.insertId });
//     }
//   );
// });

// // Update a post
// app.put("/api/post_post/:id", (req, res) => {
//   const { id } = req.params;
//   const { user_id, category_id, title, foto, description } = req.body;
//   const query =
//     "UPDATE post_post SET user_id = ?, category_id = ?, title = ?, foto = ?, description = ? WHERE id = ?";

//   db.query(
//     query,
//     [user_id, category_id, title, foto, description, id],
//     (err, result) => {
//       if (err) {
//         return res.status(500).json({ error: err.message });
//       }
//       if (result.affectedRows === 0) {
//         return res.status(404).json({ message: "Post not found" });
//       }
//       res.json({ message: "Post updated" });
//     }
//   );
// });
app.post("/api/post_post", upload.single("foto"), (req, res) => {
  // Check if the file is uploaded
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  // Extract other form fields from req.body
  const { user_id, category_id, title, description } = req.body;

  // Get the uploaded file's path or filename
  const foto = req.file ? req.file.filename : null;

  // Prepare the SQL query to insert the data into the database
  const query =
    "INSERT INTO post_post (user_id, category_id, title, foto, description) VALUES (?, ?, ?, ?, ?)";

  db.query(
    query,
    [user_id, category_id, title, foto, description],
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ message: "Post created", id: result.insertId });
    }
  );
});

// PUT route to update a post with a file (optional)
app.put("/api/post_post/:id", upload.single("foto"), (req, res) => {
  console.log("Request Body:", req.body); // Check if the title is in the request body
  console.log("Uploaded File:", req.file); // Check if the file is uploaded

  const { title, category_id, description, user_id } = req.body;

  if (!title) {
    return res.status(400).json({ error: "Title is required" });
  }

  const foto = req.file ? req.file.filename : null; // Handle the file upload

  const query =
    "UPDATE post_post SET title = ?, category_id = ?, description = ?, foto = ? WHERE id = ?";
  db.query(
    query,
    [title, category_id, description, foto, req.params.id],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.status(200).json({ message: "Post updated successfully" });
    }
  );
});

// Delete a post
app.delete("/api/post_post/:id", (req, res) => {
  const { id } = req.params;
  const query = "DELETE FROM post_post WHERE id = ?";

  db.query(query, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Post not found" });
    }
    res.json({ message: "Post deleted" });
  });
});

//jenis sampah

app.get("/api/jenis_sampah", (req, res) => {
  const page = parseInt(req.query.page) || 1; // Default to page 1
  const limit = parseInt(req.query.limit) || 4; // Default to 4 posts per page
  const offset = (page - 1) * limit;

  // Modify query to select posts with category_id = 3
  const query = `
    SELECT * FROM post_post
    WHERE category_id = 3
    LIMIT ? OFFSET ?
  `;

  db.query(query, [limit, offset], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (result.length === 0) {
      return res
        .status(404)
        .json({ message: "No posts found for this category" });
    }

    // Respond with the posts and pagination information
    res.status(200).json({
      posts: result,
      currentPage: page,
      totalPages: Math.ceil(result.length / limit), // Calculate total pages
    });
  });
});

app.get("/api/jenis_sampah/:id", (req, res) => {
  const { id } = req.params;

  // Modify query to select post with category_id = 3
  const query = "SELECT * FROM post_post WHERE id = ? AND category_id = 3";

  db.query(query, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (result.length === 0) {
      return res
        .status(404)
        .json({ message: "Post not found for this category" });
    }

    res.status(200).json(result[0]);
  });
});

app.post("/api/jenis_sampah", upload.single("foto"), (req, res) => {
  const { user_id, category_id, title, description } = req.body;

  // Validate required fields
  if (!user_id || !category_id || !title || !description) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  // Handle the uploaded file (if any)
  const foto = req.file ? req.file.filename : null;

  // Insert into database (pseudo-code)
  db.query(
    "INSERT INTO post_post (user_id, category_id, title, description, foto) VALUES (?, 3, ?, ?, ?)",
    [user_id, category_id, title, description, foto],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ id: result.insertId, created_date: new Date() });
    }
  );
});

app.put("/api/jenis_sampah/:id", (req, res) => {
  const id = req.params.id;
  // Handle update logic here
  res.send({ message: `Updated item with id ${id}` });
});

app.get("/api/post_post/manfaat", (req, res) => {
  const categoryId = req.query.category_id; // Get category_id from query parameters

  if (!categoryId) {
    return res.status(400).json({ error: "Category ID is required" });
  }

  // Query the database to get posts with category_id = categoryId
  db.query(
    "SELECT * FROM post_post WHERE category_id = ?",
    [categoryId],
    (err, results) => {
      if (err) {
        console.error("Error querying the database:", err.stack);
        return res.status(500).json({ error: "Database query failed" });
      }
      res.json(results); // Send the filtered posts as JSON
    }
  );
});

// Start the server
app.listen(process.env.PORT, () => {
  console.log("Server is running on port " + process.env.PORT);
});
