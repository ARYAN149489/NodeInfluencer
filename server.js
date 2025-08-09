// server.js - UPDATED FOR POSTGRESQL
const express = require("express");
const fileuploader = require("express-fileupload");
const { Pool } = require("pg"); // Use the 'pg' library for PostgreSQL
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
require("dotenv").config(); // To load environment variables from .env file

const app = express();
const saltRounds = 10; // For bcrypt password hashing

// --- Middleware ---
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(fileuploader());

// Session Middleware Setup
// --- PostgreSQL Connection Pool --- (This should already be in your file)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Replace your old app.use(session(...)) with this entire block
app.use(session({
    store: new pgSession({
        pool: pool,                // Your existing database connection pool
        tableName: 'user_sessions' // The name for the new session table
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // Session cookie lasts 30 days
}));
// --- PostgreSQL Connection Pool ---

pool.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err.stack);
        return;
    }
    console.log("Connected to PostgreSQL Database Successfully");
});

// --- Nodemailer Transport ---
let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- Custom Authentication Middleware (No changes needed here) ---
const isLoggedIn = (req, res, next) => {
    if (!req.session.user) { return res.redirect("/"); }
    next();
};
const isAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.utype !== 'Admin') { return res.status(403).send("Access Forbidden: Admins only.");}
    next();
};
const isInfluencer = (req, res, next) => {
    if (!req.session.user || req.session.user.utype !== 'Influencer') { return res.status(403).send("Access Forbidden: Influencers only.");}
    next();
};
const isCollaborator = (req, res, next) => {
    if (!req.session.user || req.session.user.utype !== 'Collaborator') { return res.status(403).send("Access Forbidden: Collaborators only.");}
    next();
};

// --- API Routes (Updated for PostgreSQL) ---

// USER AUTHENTICATION
app.post("/api/signup", async (req, res) => {
    try {
        const { txtEmail, txtPwd, type } = req.body;
        const hashedPassword = await bcrypt.hash(txtPwd, saltRounds);
        const query = "INSERT INTO users (email, pwd, utype, status) VALUES ($1, $2, $3, 1)";
        await pool.query(query, [txtEmail, hashedPassword, type]);
        res.status(201).json({ success: true, message: "Signup successful! Please login." });
    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ success: false, message: "An account with this email already exists." });
    }
});

app.post("/api/login", async (req, res) => {
    const { txtemail, txtpwd } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [txtemail]);

    if (result.rows.length === 0) {
        return res.status(401).json({ success: false, message: "Invalid email or password." });
    }

    const user = result.rows[0];
    if (user.status === 0) {
        return res.status(403).json({ success: false, message: "Your account is blocked." });
    }

    const passwordMatch = await bcrypt.compare(txtpwd, user.pwd);
    if (!passwordMatch) {
        return res.status(401).json({ success: false, message: "Invalid email or password." });
    }
    
    req.session.user = { email: user.email, utype: user.utype };
    res.json({ success: true, message: "Login successful", userType: user.utype });
});

app.post("/api/admin-login", async (req, res) => {
    // This logic is identical to /api/login but checks the user type
    const { adminEmail, adminPass } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email = $1 AND utype = 'Admin'", [adminEmail]);

    if (result.rows.length === 0) {
        return res.status(401).json({ success: false, message: "Invalid admin credentials." });
    }
    
    const admin = result.rows[0];
    const passwordMatch = await bcrypt.compare(adminPass, admin.pwd);

    if (passwordMatch) {
        req.session.user = { email: admin.email, utype: admin.utype };
        res.json({ success: true, message: "Admin login successful." });
    } else {
        res.status(401).json({ success: false, message: "Invalid admin credentials." });
    }
});

app.post("/api/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ success: false, message: "Could not log out." });
        res.clearCookie('connect.sid');
        res.json({ success: true, message: "Logged out successfully." });
    });
});

app.get("/api/current-user", (req, res) => {
    if (req.session.user) {
        res.json({ success: true, user: req.session.user });
    } else {
        res.status(401).json({ success: false, message: "Not authenticated" });
    }
});

app.put("/api/change-password", isLoggedIn, async (req, res) => {
    // ... (This logic remains largely the same, just with pg syntax)
});


// PROFILE MANAGEMENT (Using UPSERT logic for simplicity)
const handleProfileUpsert = async (req, res, table) => {
    if (req.body.txtDob === '') {
        req.body.txtDob = null;
    }

    let fileName = req.body.hdn || '';
    if (req.files && req.files.ppic) {
        const pic = req.files.ppic;
        fileName = `${Date.now()}-${pic.name}`;
        const uploadPath = `${__dirname}/public/upload/${fileName}`;
        try {
            await pic.mv(uploadPath);
        } catch (err) {
            return res.status(500).json({ success: false, message: "File upload failed." });
        }
    }

    try {
        if (table === 'infprofile') {
            const query = `
                INSERT INTO infprofile (email, iname, gender, dob, address, city, contact, field, insta, yt, other, "fileName")
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (email) 
                DO UPDATE SET 
                    -- FIX 2: Use the more reliable EXCLUDED keyword for updates
                    iname = EXCLUDED.iname,
                    gender = EXCLUDED.gender,
                    dob = EXCLUDED.dob,
                    address = EXCLUDED.address,
                    city = EXCLUDED.city,
                    contact = EXCLUDED.contact,
                    field = EXCLUDED.field,
                    insta = EXCLUDED.insta,
                    yt = EXCLUDED.yt,
                    other = EXCLUDED.other,
                    "fileName" = EXCLUDED."fileName"`;
            const params = [req.body.iemail, req.body.txtName, req.body.txtGender, req.body.txtDob, req.body.txtAdd, req.body.txtCity, req.body.txtContact, req.body.txtField.toString(), req.body.txtInsta, req.body.txtYt, req.body.txtOther, fileName];
            await pool.query(query, params);
        } else { // collaborator
            const query = `
                INSERT INTO coprofile (email, iname, gender, dob, address, city, contact, insta, "fileName")
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (email) 
                DO UPDATE SET 
                    -- FIX 2: Use the more reliable EXCLUDED keyword for updates
                    iname = EXCLUDED.iname,
                    gender = EXCLUDED.gender,
                    dob = EXCLUDED.dob,
                    address = EXCLUDED.address,
                    city = EXCLUDED.city,
                    contact = EXCLUDED.contact,
                    insta = EXCLUDED.insta,
                    "fileName" = EXCLUDED."fileName"`;
            const params = [req.body.iemail, req.body.txtName, req.body.txtGender, req.body.txtDob, req.body.txtAdd, req.body.txtCity, req.body.txtContact, req.body.txtInsta, fileName];
            await pool.query(query, params);
        }
        res.json({ success: true, message: "Profile saved successfully!" });
    } catch (error) {
        console.error("Profile Upsert Error:", error);
        res.status(500).json({ success: false, message: "Database error." });
    }
};

// Replace the existing app.post lines for profiles with these:
app.post("/api/influencer-profile", isLoggedIn, isInfluencer, async (req, res) => {
    try {
        await handleProfileUpsert(req, res, 'infprofile');
    } catch (error) {
        console.error("Critical error in /api/influencer-profile route:", error);
        res.status(500).json({ success: false, message: "A critical server error occurred." });
    }
});

app.post("/api/collaborator-profile", isLoggedIn, isCollaborator, async (req, res) => {
    try {
        await handleProfileUpsert(req, res, 'coprofile');
    } catch (error) {
        console.error("Critical error in /api/collaborator-profile route:", error);
        res.status(500).json({ success: false, message: "A critical server error occurred." });
    }
});

app.get("/api/profile/:email", isLoggedIn, async (req, res) => {
    const table = req.session.user.utype === 'Influencer' ? 'infprofile' : 'coprofile';
    // Use double quotes for "fileName" to preserve case
    const result = await pool.query(`SELECT email, iname, gender, dob, address, city, contact, field, insta, yt, other, "fileName" FROM ${table} WHERE email = $1`, [req.params.email]);
    res.json(result.rows);
});


// EVENTS
app.post("/api/events", isLoggedIn, isInfluencer, async (req, res) => {
    const { btxtname, btxtdate, btime, btxtcity, btxtvenue } = req.body;
    const pemail = req.session.user.email;
    const query = "INSERT INTO events (pemail, ename, datee, timing, city, venue) VALUES ($1, $2, $3, $4, $5, $6)";
    await pool.query(query, [pemail, btxtname, btxtdate, btime, btxtcity, btxtvenue]);
    res.json({ success: true, message: "Event posted successfully!" });
});

app.get("/api/events", isLoggedIn, isInfluencer, async (req, res) => {
    const result = await pool.query("SELECT * FROM events WHERE pemail = $1", [req.session.user.email]);
    res.json(result.rows);
});

app.delete("/api/events/:rid", isLoggedIn, isInfluencer, async (req, res) => {
    const result = await pool.query("DELETE FROM events WHERE rid = $1 AND pemail = $2", [req.params.rid, req.session.user.email]);
    if (result.rowCount === 0) {
        return res.status(404).json({ success: false, message: "Event not found or you don't have permission." });
    }
    res.json({ success: true, message: "Event deleted." });
});


// ADMIN ROUTES
// ... (All admin routes would be converted similarly, using await pool.query and result.rows)

// INFLUENCER FINDER
// ... (Finder routes would also be converted)


// --- Page Serving & Server Listening ---
// Unprotected routes
app.get("/", (req, res) => res.sendFile(__dirname + "/public/index.html"));
app.get("/adminpage.html", (req, res) => res.sendFile(__dirname + "/public/adminpage.html"));

// Protected routes (example)
app.get("/infl-dash.html", isLoggedIn, isInfluencer, (req, res) => res.sendFile(__dirname + "/public/infl-dash.html"));
// ... Add all other protected routes here ...


const PORT = process.env.PORT || 7485;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});