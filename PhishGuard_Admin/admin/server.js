// ============================================================
//  FIREBASE ADMIN DASHBOARD — BACKEND SERVER
//  Node.js + Express + Firebase Admin SDK + Firestore
// ============================================================

const express = require("express");
const cors    = require("cors");
const admin   = require("firebase-admin");
const path    = require("path");

// ── Load your service account key ──────────────────────────
const serviceAccount = require("./serviceAccountKey.json");

// ── Initialize Firebase Admin (Auth + Firestore) ───────────
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const auth = admin.auth();
const db   = admin.firestore();   // ← Firestore access
const app  = express();

// ── Middleware ─────────────────────────────────────────────
app.use(cors({ origin: "*" }));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── Verify admin token on every /api route ─────────────────
async function verifyAdmin(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }
    const idToken = authHeader.split("Bearer ")[1];
    const decoded = await auth.verifyIdToken(idToken);

    if (!decoded.admin) {
      return res.status(403).json({ error: "Not an admin account" });
    }
    req.adminUser = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token: " + err.message });
  }
}

// ── First-time setup: make yourself admin ──────────────────
//  POST /setup  { "email": "you@email.com", "secret": "my-setup-secret-change-this" }
app.post("/setup", async (req, res) => {
  const { email, secret } = req.body;
  const SETUP_SECRET = "my-setup-secret-change-this"; // ← change this!

  if (secret !== SETUP_SECRET) {
    return res.status(403).json({ error: "Wrong secret" });
  }
  try {
    const user = await auth.getUserByEmail(email);
    await auth.setCustomUserClaims(user.uid, { admin: true });
    res.json({
      success: true,
      message: `✅ ${email} is now an admin! Sign out and back in to refresh your token.`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  GET /api/users
//  Returns Firebase Auth data + Firestore profile
//  (name, phone, dob, country from your Android signup)
// ══════════════════════════════════════════════════════════
app.get("/api/users", verifyAdmin, async (req, res) => {
  try {
    const listResult = await auth.listUsers(1000);

    // Fetch Firestore profile for each user in parallel
    const users = await Promise.all(
      listResult.users.map(async (u) => {

        let profile = {};
        try {
          const doc = await db.collection("users").doc(u.uid).get();
          if (doc.exists) profile = doc.data();
        } catch (_) {
          // If Firestore doc doesn't exist, profile stays {}
        }

        return {
          uid:           u.uid,
          email:         u.email         || "",
          displayName:   u.displayName   || profile.name || "",
          phone:         profile.phone   || "",
          dob:           profile.dob     || "",
          country:       profile.country || "",
          photoURL:      u.photoURL      || "",
          provider:      u.providerData?.[0]?.providerId || "unknown",
          emailVerified: u.emailVerified,
          disabled:      u.disabled,
          createdAt:     u.metadata.creationTime,
          lastSignIn:    u.metadata.lastSignInTime,
          role:          u.customClaims?.role  || "user",
          isAdmin:       u.customClaims?.admin || false,
        };
      })
    );

    res.json(users);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Disable / Enable account ───────────────────────────────
app.patch("/api/users/:uid/disable", verifyAdmin, async (req, res) => {
  const { uid } = req.params;
  const { disabled } = req.body;
  try {
    await auth.updateUser(uid, { disabled });
    res.json({ success: true, uid, disabled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Delete user ────────────────────────────────────────────
app.delete("/api/users/:uid", verifyAdmin, async (req, res) => {
  const { uid } = req.params;
  try {
    await auth.deleteUser(uid);
    res.json({ success: true, uid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Set role (custom claim) ────────────────────────────────
app.post("/api/users/:uid/role", verifyAdmin, async (req, res) => {
  const { uid } = req.params;
  const { role } = req.body;
  try {
    const currentUser    = await auth.getUser(uid);
    const existingClaims = currentUser.customClaims || {};
    await auth.setCustomUserClaims(uid, {
      ...existingClaims,
      role,
      admin: role === "admin" ? true : existingClaims.admin,
    });
    res.json({ success: true, uid, role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Send password reset email ──────────────────────────────
app.post("/api/users/:uid/reset-password", verifyAdmin, async (req, res) => {
  const { uid } = req.params;
  try {
    const user = await auth.getUser(uid);
    if (!user.email) return res.status(400).json({ error: "User has no email" });
    const link = await auth.generatePasswordResetLink(user.email);
    res.json({ success: true, link, email: user.email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Verify email manually ──────────────────────────────────
app.post("/api/users/:uid/verify-email", verifyAdmin, async (req, res) => {
  const { uid } = req.params;
  try {
    await auth.updateUser(uid, { emailVerified: true });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Create new user ────────────────────────────────────────
app.post("/api/users", verifyAdmin, async (req, res) => {
  const { email, password, displayName, role } = req.body;
  try {
    const newUser = await auth.createUser({
      email,
      password:    password || Math.random().toString(36).slice(-10),
      displayName: displayName || "",
      emailVerified: false,
    });
    if (role) {
      await auth.setCustomUserClaims(newUser.uid, { role });
    }
    res.json({ success: true, uid: newUser.uid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start server ───────────────────────────────────────────
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`\n🔥 Firebase Admin Dashboard running!`);
  console.log(`   Open: http://localhost:${PORT}/admin.html\n`);
});
