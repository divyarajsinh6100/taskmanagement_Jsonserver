const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();

server.use(middlewares);
server.use(jsonServer.bodyParser);
server.db = router.db;

const SECRET_KEY = "1205dev"; // Ensure consistency

server.post("/register", async (req, res) => {
  const { fullName, email, password, role = "user" } = req.body; // Default role to "user"

  // Check if user already exists
  const existingUser = router.db.get("users").find({ email }).value();
  if (existingUser) {
    return res.status(400).json({ error: "User already exists" });
  }

  try {
    // Hash password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: Date.now().toString(16), // Generate unique ID
      fullName,
      email,
      password: hashedPassword,
      role,
    };

    // Store new user in users array
    router.db.get("users").push(newUser).write();

    res.status(201).json({ message: "User registered successfully", user: newUser });
  } catch (error) {
    console.error(" Error hashing password:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 🛠️ ✅ User Login & Token Generation
server.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Find user in database
  const user = router.db.get("users").find({ email }).value();
  if (!user) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  // Verify password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  // Generate JWT token
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET_KEY, { expiresIn: "1h" });

  res.json({ accessToken: token, user });
});

server.use((req, res, next) => {
  if (req.path.startsWith("/tasks")) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(403).json({ error: "Access denied, token missing" });
    }

    const token = authHeader.split(" ")[1];

    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.user = decoded; // Store user data in request
      next();
    } catch (error) {
      return res.status(403).json({ error: "Invalid token" });
    }
  } else {
    next();
  }
});

server.use(router);
server.listen(3000, () => {
  console.log("JSON Server with JWT Auth is running on port 3000");
});
