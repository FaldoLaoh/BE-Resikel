const jwt = require("jsonwebtoken");

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ Status: "Error", Message: "Unauthorized" });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .json({ Status: "Error", Message: "Token is invalid" });
    }
    req.user = decoded; // Attach user information from the token
    next();
  });
};

module.exports = verifyUser;
