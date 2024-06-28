const bcrypt = require("bcryptjs");
const { User, UserService, ClientPaye } = require("../model/User");
const { default: axios } = require("axios");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const session = require("express-session");
const { decode } = require("jsonwebtoken");

/**
 *
 * @param {*} req
 * @param {*} res
 */

module.exports.signup_get = (req, res) => {
  res.render("signup");
};

module.exports.login_get = (req, res) => {
  res.render("login");
};

module.exports.signup_post = async (req, res) => {
  const { username, email, password, role } = req.body;

  let user = await User.findOne({ email });
  if (user) {
    return res.status(409).send("That email is already registered.");
  }

  //+ salt a password ou Argon2id
  const salt = await bcrypt.genSalt();
  const hashPwd = await bcrypt.hash(password, salt);

  user = new User({
    username,
    email,
    password: hashPwd,
    role: role || "user",
  });

  await user.save();
  res.redirect("/login");
};

const generateAccessToken = (user) => {
  try {
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.TOKEN_SECRET,
      {
        expiresIn: "1h",
      }
    );
    // console.log("Generated Token:", token);
    return token;
  } catch (error) {
    console.error("Error generating token:", error);
    throw new Error("Token generation failed");
  }
};

module.exports.login_post = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(404).json("Invalid Password");
    }

    if (user) {
      req.session.user = user;
      res.json({ message: "Login successful", auth: true });
    }
  } catch (error) {
    res.status(500).json("Internan Server Error");
  }

  // if (!user) {
  //   return res.status(403).json("User not found");
  // }

  // const isMatch = await bcrypt.compare(password, user.password);
  // if (!isMatch) {
  //   return res.status(404).json("Incorrect Password");
  // }

  // const jsonwebtoken = jwt.sign(
  //   {
  //     id: user._id,
  //     email: user.email,
  //     rol: user.role,
  //   },
  //   process.env.TOKEN_SECRET,
  //   {
  //     expiresIn: "1h",
  //   }
  // );

  // const accessToken = generateAccessToken(user);
  // res.json({ auth: true, jsonwebtoken, message: "Login Successful" });
  // console.log(decode(jsonwebtoken));
};

module.exports.logout = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Logout failed");
    }
    res.clearCookie("connect.sid"); // Adjust based on your session cookie name
    res.status(200).send("Logged out");
  });
};

module.exports.check_isAuth = (req, res) => {
  if (req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.status(401).json({ message: "Not authentificated" });
  }
};

module.exports.reset_pwd = async (req, res) => {
  try {
    const { email, password } = req.body;
    User.findOne({ email })
      .then((user) => {
        // const salt = bcrypt.genSalt();
        bcrypt
          .hash(password, 10)
          .then((hashPwd) => {
            User.updateOne(
              { email: user.email },
              { password: hashPwd },
              (err, data) => {
                if (err) throw err;
                return res
                  .status(201)
                  .send({ msg: "Password reset", success: true });
              }
            );
          })
          .catch((e) => {
            return res.status(500).send({ e: "Enable to hashed password" });
          });
      })
      .catch((error) => {
        return res.status(404).send({ error: "User not found" });
      });
  } catch (error) {
    return res.status(500).send({ error });
  }
};

module.exports.article_get = async (req, res) => {
  const { category } = req.query;
  const user = req.session.user;
  const useService = new UserService(user);
  if (category === "world" || category === "health") {
    if (!useService.hasAdminAccess()) {
      return res.status(403).json({
        message: "Accès refusé. Vous n'avez pas les permissions nécessaires.",
      });
    }
  }

  const key = process.env.NYT_API_KEY;
  try {
    const response = await axios.get(
      `https://api.nytimes.com/svc/topstories/v2/${category}.json?api-key=${key}`
    );
    res.json(response.data.results);
  } catch (error) {
    res.status(500).json({ message: error.message, diso: error });
  }
};

module.exports.devenir_admin = async (req, res, next) => {
  const user = req.session.user;
  console.log("User session in devenir_admin:", user);
  try {
    const userId = await User.findById(user);
    if (!user) {
      return res.status(404).json("User not found");
    }
    userId.role = "admin";
    await userId.save();

    next();
    res.send({ message: "User promoted to admin successful", data: userId });
  } catch (error) {
    console.error("Promote user to admin error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

module.exports.userId = async (req, res) => {
  try {
    const userId = req.session.user;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json("User not found");
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
};

module.exports.payments = async (req, res) => {
  try {
    const data = new ClientPaye(req.body);
    await data.save().then(async () => {
      try {
        const response = await axios.get(
          `https://api.nytimes.com/svc/topstories/v2/world.json?api-key=${key}`
        );
        res.json(response.data.results);
      } catch (error) {
        res.status(500).json({ message: error.message, diso: error });
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json("Internal Server Error");
  }
};
// const { name, email, telephone } = req.body;
// const user = await ClientPaye.findOne({ email });

// user = new ClientPaye({
//   name,
//   email,
//   telephone,
// });
// await user.save();
// res.json({ user });
