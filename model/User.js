const mongoose = require("mongoose");
const { isEmail } = require("validator");
const bcrypt = require("bcrypt");

// Define the user schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: [true, "Please enter an email"],
    unique: true,
    lowercase: true,
    validate: [isEmail, "Please enter a valid email"],
  },
  password: {
    type: String,
    required: [true, "Please enter a password"],
    minlength: [6, "Minimum password length is 6 characters"],
  },
  role: [{ type: String, enum: ["user", "admin"], default: "user" }],
});

// Create the model from the schema
const User = mongoose.model("User", userSchema);

const payeSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: [true, "Please enter an email"],
    unique: true,
    lowercase: true,
    validate: [isEmail, "Please enter a valid email"],
  },
  tel: {
    type: String,
    required: [true, "Please enter a password"],
    minlength: [10, "Minimum  length is 6 characters"],
  },
});

const ClientPaye = mongoose.model("ClientPaye", payeSchema);

class UserService {
  constructor(user) {
    this.user = user;
  }

  hasAdminAccess() {
    return this.user.role === "admin";
  }
}
// Export the model
module.exports = { User, UserService, ClientPaye };
