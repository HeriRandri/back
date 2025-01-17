// const express = require("express");
// const cors = require("cors");
// const mongoose = require("mongoose");
// const path = require("path");
// const authRouters = require("./routers/authRouters");
// const fs = require("fs");
// const User = require("./model/User");
// const router = require("./routers/arctiles");
// const session = require("express-session");
// const MongoDBSession = require("connect-mongodb-session")(session);

// const app = express();
// app.use(express.json());
// app.use(cors());

// // Set the view engine to EJS
// app.set("view engine", "ejs");

// // Set the views directory explicitly
// const viewsDirectory = path.join(__dirname, "views");
// app.set("views", viewsDirectory);

// // Log the views directory path for debugging
// console.log("Views directory set to:", viewsDirectory);

// // Add a simple route to render index.ejs
// app.use(authRouters);
// app.use("/external", router);

// const mongodbUrl = "mongodb://localhost:27017/examenDtc";
// mongoose
//   .connect(mongodbUrl, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
//   })
//   .then(() => {
//     console.log("CONNECTED TO MONGODB");
//     app.listen(4000, () => {
//       console.log("Server running at http://localhost:4000");
//     });
//   })
//   .catch((err) => {
//     console.log(`Error connecting to MongoDB: ${err}`);
//   });
// const store = new MongoDBSession({
//   uri: mongodbUrl,
//   collection: "mySessions",
// });

// app.use(
//   session({
//     secret: "niavo",
//     resave: false,
//     saveUninitialized: false,
//     store: store,
//   })
// );

// // List files in views directory for debugging
// fs.readdir(viewsDirectory, (err, files) => {
//   if (err) {
//     console.error("Could not list the directory.", err);
//     process.exit(1);
//   }
//   console.log("Files in views directory:", files);
// });

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const router = require("./routers/authRouters");
const MongoDBSession = require("connect-mongodb-session")(session);
require("dotenv").config();

const mongodbUrl = "mongodb://localhost:27017/examenDtc";

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT"],
  })
);

// Set the view engine to EJS
app.set("view engine", "ejs");

// Set the views directory explicitly
const viewsDirectory = path.join(__dirname, "views");
app.set("views", viewsDirectory);

// Log the views directory path for debugging
console.log("Views directory set to:", viewsDirectory);

// Add a simple route to render index.ejs
// app.use(express.static(path.join(__dirname, "build")));

// Handles any requests that don't match the ones above
// app.get("*", (req, res) => {
//   res.sendFile(path.join(__dirname + "/build/index.html"));
// });
const uri = process.env.MONGODB_URi;
console.log("url de mongodb", uri);
const store = new MongoDBSession({
  uri: uri,
  collection: "mySessions",
});
app.use(
  session({
    secret: "secrets",
    resave: false,
    saveUninitialized: false,
    store: store,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
      secure: false,
      httpOnly: true,
    },
  })
);

app.use(router);

mongoose
  .connect(uri, {
    ssl: true,
  })
  .then(() => {
    console.log("CONNECTED TO MONGODB");
    app.listen(4000, () => {
      console.log("Server running at http://localhost:4000");
    });
  })
  .catch((err) => {
    console.log(`Error connecting to MongoDB: ${err}`);
  });

// List files in views directory for debugging
fs.readdir(viewsDirectory, (err, files) => {
  if (err) {
    console.error("Could not list the directory.", err);
    process.exit(1);
  }
  console.log("Files in views directory:", files);
});
