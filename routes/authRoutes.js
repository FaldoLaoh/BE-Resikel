const express = require("express");
const router = express.Router();
const { login, logout } = require("../controllers/authController"); // Check the path
const verifyUser = require("../middlewares/authMiddleware");

router.post("/login", login);
router.post("/logout", logout);
router.get("/", verifyUser, (req, res) => {
  res.status(200).json({ Status: "Success", Message: "Authenticated" });
});

module.exports = router;
