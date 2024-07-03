// const jwt = require("jsonwebtoken");

// const authenticateToken =(requiredRole)=>{
// return (req, res, next) => {
//   const authHeader = req.headers["authorization"];
//   const token = authHeader && authHeader.split(" ")[1];

//   if (token == null) {
//     return res.sendStatus(401); // Unauthorized
//   }

//   jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
//     if (err) {
//       return res.sendStatus(403); // Forbidden
//     }
//     req.user = user;
// if (requiredRole && req.user.role !== requiredRole) {
//   return res.status(403).json({ error: 'Accès refusé. Vous n\'avez pas le rôle requis.' });
// }
//     next();
//   });
// };
// }

const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ message: "Unauthorized" });
  }
};
const isVip = (req, res, next) => {
  console.log(req.session.user.role);
  const user = req.session.user;
  if (user && user.role === "admin") {
    return next();
  } else {
    return res.status(403).json({
      message: "Accès refusé. Vous n'avez pas les permissions nécessaires.",
    });
  }
};

module.exports = { isVip, isAuthenticated };

/***
 * const { auth } = require('express-openid-connect');

const config = {
  authRequired: false,
  auth0Logout: true,
  secret: 'a long, randomly-generated string stored in env',
  baseURL: 'http://localhost:3000',
  clientID: 'VKiMd3pY7CDBg85gRBPZyczSRC22ulYY',
  issuerBaseURL: 'https://dev-35al4upbkuu157ps.us.auth0.com'
};

// auth router attaches /login, /logout, and /callback routes to the baseURL
app.use(auth(config));

// req.isAuthenticated is provided from the auth router
app.get('/', (req, res) => {
  res.send(req.oidc.isAuthenticated() ? 'Logged in' : 'Logged out');
});


profile controller

const { requiresAuth } = require('express-openid-connect');

app.get('/profile', requiresAuth(), (req, res) => {
  res.send(JSON.stringify(req.oidc.user));
});
 * 
 */
