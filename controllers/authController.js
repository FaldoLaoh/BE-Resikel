const db = require("../models/db");
const jwt = require("jsonwebtoken");

const login = (req, res) => {
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) {
      return res.json({ Error: "Login Error in server" });
    }
    if (data.length > 0) {
      const user = data[0];
      if (user.password === req.body.password) {
        const token = jwt.sign({ email: user.email }, process.env.SECRET_KEY, {
          expiresIn: "2h",
        });

        res.cookie("token", token, {
          httpOnly: true,
          secure: false, // set true in production
        });

        return res.json({
          Success: "Login successful",
          Token: token,
          User: user,
        });
      } else {
        return res.json({ Error: "Incorrect password" });
      }
    } else {
      return res.json({ Error: "No email found" });
    }
  });
};

const logout = (req, res) => {
  res.clearCookie("token", { httpOnly: true, secure: false });
  res.json({ Status: "Success", Message: "Logged out successfully" });
};

module.exports = { login, logout };
