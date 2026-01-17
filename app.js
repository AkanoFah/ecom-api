import express from "express";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import { v4 as uuid } from "uuid";
import swaggerUi from "swagger-ui-express";
import swaggerJsdoc from "swagger-jsdoc";

const app = express();
const PORT = 3000;
const JWT_SECRET = "supersecret";

// middleware
app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(morgan("dev"));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
});
app.use(limiter);

const users = [
  { id: 1, email: "admin@test.com", password: "1234", role: "admin" },
  { id: 2, email: "user@test.com", password: "1234", role: "user" },
];

const products = [];
const orders = [];
const idempotencyKeys = new Set();

// solid auth
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

const authorize = (roles = []) => (req, res, next) => {
  if (!roles.includes(req.user.role))
    return res.status(403).json({ message: "Forbidden" });
  next();
};

// login
app.post("/api/v1/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Invalid input" });

  const user = users.find(
    (u) => u.email === email && u.password === password
  );

  if (!user) return res.status(401).json({ message: "Login failed" });

  const token = jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// restful
app.get("/api/v1/products", (req, res) => {
  res.json(products);
});

app.post(
  "/api/v1/products",
  authenticate,
  authorize(["admin"]),
  (req, res) => {
    const { name, price } = req.body;

    if (!name || price <= 0)
      return res.status(400).json({ message: "Invalid product" });

    const product = { id: uuid(), name, price };
    products.push(product);

    res.status(201).json(product);
  }
);

// orders
app.post(
  "/api/v1/orders",
  authenticate,
  authorize(["user"]),
  (req, res) => {
    const idempotencyKey = req.headers["idempotency-key"];
    if (!idempotencyKey)
      return res.status(400).json({ message: "Missing Idempotency-Key" });

    if (idempotencyKeys.has(idempotencyKey))
      return res.status(409).json({ message: "Duplicate request" });

    const { productId, quantity } = req.body;
    if (!productId || quantity <= 0)
      return res.status(400).json({ message: "Invalid order" });

    idempotencyKeys.add(idempotencyKey);

    const order = {
      id: uuid(),
      userId: req.user.id,
      productId,
      quantity,
      status: "PAID",
    };

    orders.push(order);
    res.status(201).json(order);
  }
);

// error handling
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: "Internal Server Error" });
});

// swager
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: "3.0.0",
    info: {
      title: "E-commerce API",
      version: "1.0.0",
    },
  },
  apis: [],
});

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// startserver
app.listen(PORT, () =>
  console.log(`API running at http://localhost:${PORT}`)
);
