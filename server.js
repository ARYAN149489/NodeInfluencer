// server.js - FINAL VERSION (PostgreSQL with all routes and fixes)
const express = require("express");
const fileuploader = require("express-fileupload");
const { Pool } = require("pg"); // Use the 'pg' library for PostgreSQL
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
require("dotenv").config(); // To load environment variables from .env file


const cloudinary = require('cloudinary').v2;
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const app = express();
const saltRounds = 10; // For bcrypt password hashing

// --- Middleware ---
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
// Configure express-fileupload to use temporary files
app.use(fileuploader({ useTempFiles: true }));

// --- PostgreSQL Connection Pool ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Session Middleware Setup
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

// --- Custom Authentication Middleware ---
const isLoggedIn = (req, res, next) => {
    if (!req.session.user) { return res.redirect("/"); }
    next();
};
const isAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.utype !== 'Admin') { return res.status(403).json({ message: "Access Forbidden" });}
    next();
};
const isInfluencer = (req, res, next) => {
    if (!req.session.user || req.session.user.utype !== 'Influencer') { return res.status(403).json({ message: "Access Forbidden" });}
    next();
};
const isCollaborator = (req, res, next) => {
    if (!req.session.user || req.session.user.utype !== 'Collaborator') { return res.status(403).json({ message: "Access Forbidden" });}
    next();
};

// --- API Routes ---

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
    try {
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
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ success: false, message: "Server error during login." });
    }
});

app.post("/api/admin-login", async (req, res) => {
    try {
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
    } catch (error) {
        console.error("Admin Login Error:", error);
        res.status(500).json({ success: false, message: "Server error during admin login." });
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
    try {
        const { opwd, npwd } = req.body;
        const email = req.session.user.email;

        const result = await pool.query("SELECT pwd FROM users WHERE email = $1", [email]);
        if (result.rows.length === 0) {
            return res.status(400).json({ success: false, message: "User not found." });
        }

        const passwordMatch = await bcrypt.compare(opwd, result.rows[0].pwd);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, message: "Incorrect old password." });
        }

        const newHashedPassword = await bcrypt.hash(npwd, saltRounds);
        await pool.query("UPDATE users SET pwd = $1 WHERE email = $2", [newHashedPassword, email]);
        res.json({ success: true, message: "Password changed successfully." });
    } catch (error) {
        console.error("Password Change Error:", error);
        res.status(500).json({ success: false, message: "Failed to update password." });
    }
});

// PROFILE MANAGEMENT
const handleProfileUpsert = async (req, res, table) => {
    if (req.body.txtDob === '') {
        req.body.txtDob = null;
    }

    let imageUrl = req.body.hdn || '';

    if (req.files && req.files.ppic) {
        const pic = req.files.ppic;
        try {
            const result = await cloudinary.uploader.upload(pic.tempFilePath, { folder: "promo-app-profiles" });
            imageUrl = result.secure_url;
        } catch (error) {
            console.error("Cloudinary upload error:", error);
            return res.status(500).json({ success: false, message: "Image upload failed." });
        }
    }

    try {
        if (table === 'infprofile') {
            const query = `
                INSERT INTO infprofile (email, iname, gender, dob, address, city, contact, field, insta, yt, other, "fileName")
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (email) DO UPDATE SET 
                    iname = EXCLUDED.iname, gender = EXCLUDED.gender, dob = EXCLUDED.dob, address = EXCLUDED.address,
                    city = EXCLUDED.city, contact = EXCLUDED.contact, field = EXCLUDED.field, insta = EXCLUDED.insta,
                    yt = EXCLUDED.yt, other = EXCLUDED.other, "fileName" = EXCLUDED."fileName"`;
            const params = [req.body.iemail, req.body.txtName, req.body.txtGender, req.body.txtDob, req.body.txtAdd, req.body.txtCity, req.body.txtContact, req.body.txtField.toString(), req.body.txtInsta, req.body.txtYt, req.body.txtOther, imageUrl];
            await pool.query(query, params);
        } else { // collaborator
            const query = `
                INSERT INTO coprofile (email, iname, gender, dob, address, city, contact, insta, "fileName")
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (email) DO UPDATE SET
                    iname = EXCLUDED.iname, gender = EXCLUDED.gender, dob = EXCLUDED.dob, address = EXCLUDED.address,
                    city = EXCLUDED.city, contact = EXCLUDED.contact, insta = EXCLUDED.insta, "fileName" = EXCLUDED."fileName"`;
            const params = [req.body.iemail, req.body.txtName, req.body.txtGender, req.body.txtDob, req.body.txtAdd, req.body.txtCity, req.body.txtContact, req.body.txtInsta, imageUrl];
            await pool.query(query, params);
        }
        res.json({ success: true, message: "Profile saved successfully!" });
    } catch (error) {
        console.error("Profile Upsert Error:", error);
        res.status(500).json({ success: false, message: "Database error during profile update." });
    }
};

app.post("/api/influencer-profile", isLoggedIn, isInfluencer, (req, res) => handleProfileUpsert(req, res, 'infprofile'));
app.post("/api/collaborator-profile", isLoggedIn, isCollaborator, (req, res) => handleProfileUpsert(req, res, 'coprofile'));

app.get("/api/profile/:email", isLoggedIn, async (req, res) => {
    try {
        const table = req.session.user.utype === 'Influencer' ? 'infprofile' : 'coprofile';
        const result = await pool.query(`SELECT * FROM ${table} WHERE email = $1`, [req.params.email]);
        res.json(result.rows);
    } catch (error) {
        console.error("Get Profile Error:", error);
        res.status(500).json([]);
    }
});

// EVENTS
app.post("/api/events", isLoggedIn, isInfluencer, async (req, res) => {
    try {
        const { btxtname, btxtdate, btime, btxtcity, btxtvenue } = req.body;
        const pemail = req.session.user.email;
        const query = "INSERT INTO events (pemail, ename, datee, timing, city, venue) VALUES ($1, $2, $3, $4, $5, $6)";
        await pool.query(query, [pemail, btxtname, btxtdate, btime, btxtcity, btxtvenue]);
        res.json({ success: true, message: "Event posted successfully!" });
    } catch (error) {
        console.error("Post Event Error:", error);
        res.status(500).json({ success: false, message: "Failed to post event." });
    }
});

app.get("/api/events", isLoggedIn, isInfluencer, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM events WHERE pemail = $1", [req.session.user.email]);
        res.json(result.rows);
    } catch (error) {
        console.error("Get Events Error:", error);
        res.status(500).json([]);
    }
});

app.delete("/api/events/:rid", isLoggedIn, isInfluencer, async (req, res) => {
    try {
        const result = await pool.query("DELETE FROM events WHERE rid = $1 AND pemail = $2", [req.params.rid, req.session.user.email]);
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: "Event not found or you don't have permission." });
        }
        res.json({ success: true, message: "Event deleted." });
    } catch (error) {
        console.error("Delete Event Error:", error);
        res.status(500).json({ success: false, message: "Failed to delete event." });
    }
});


// ADMIN ROUTES --- FULLY CORRECTED FOR POSTGRESQL ---
app.get("/api/admin/users", isLoggedIn, isAdmin, async (req, res) => {
    try {
        const result = await pool.query("SELECT email, utype, status FROM users");
        res.json(result.rows);
    } catch (error) {
        console.error("Admin Get Users Error:", error);
        res.status(500).json({ message: "Failed to fetch users." });
    }
});

app.delete("/api/admin/users/:email", isLoggedIn, isAdmin, async (req, res) => {
    try {
        const emailToDelete = req.params.email;
        if (emailToDelete === req.session.user.email) {
            return res.status(400).json({ success: false, message: "Admin cannot delete their own account." });
        }
        await pool.query("DELETE FROM users WHERE email = $1", [emailToDelete]);
        res.json({ success: true, message: "User deleted." });
    } catch (error) {
        console.error("Admin Delete User Error:", error);
        res.status(500).json({ success: false, message: "Failed to delete user." });
    }
});

app.put("/api/admin/users/:email/status", isLoggedIn, isAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const emailToUpdate = req.params.email;
        if (emailToUpdate === req.session.user.email) {
            return res.status(400).json({ success: false, message: "Admin cannot change their own status." });
        }
        await pool.query("UPDATE users SET status = $1 WHERE email = $2", [status, emailToUpdate]);
        res.json({ success: true, message: `User status updated.` });
    } catch (error) {
        console.error("Admin Update Status Error:", error);
        res.status(500).json({ success: false, message: "Failed to update user status." });
    }
});

app.get("/api/admin/influencer-profiles", isLoggedIn, isAdmin, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM infprofile");
        res.json(result.rows);
    } catch (error) {
        console.error("Admin Get Profiles Error:", error);
        res.status(500).json({ message: "Failed to fetch profiles." });
    }
});


// INFLUENCER FINDER --- FULLY CORRECTED FOR POSTGRESQL ---
app.get("/api/influencer-search", isLoggedIn, isCollaborator, async (req, res) => {
    try {
        let { fields, city, pname } = req.query;
        fields = fields || ""; city = city || ""; pname = pname || "";

        let sql = 'SELECT * FROM infprofile';
        let conditions = [];
        let params = [];
        let paramIndex = 1;

        if (fields) {
            conditions.push(`field LIKE $${paramIndex++}`);
            params.push(`%${fields}%`);
        }
        if (city) {
            conditions.push(`city = $${paramIndex++}`);
            params.push(city);
        }
        if (pname) {
            conditions.push(`iname LIKE $${paramIndex++}`);
            params.push(`%${pname}%`);
        }

        if (conditions.length > 0) {
            sql += " WHERE " + conditions.join(" AND ");
        }

        const result = await pool.query(sql, params);
        res.json(result.rows);
    } catch (error) {
        console.error("Influencer Search Error:", error);
        res.status(500).json([]);
    }
});

app.get("/api/cities-by-field", isLoggedIn, isCollaborator, async (req, res) => {
    try {
        const { fields } = req.query;
        const result = await pool.query("SELECT DISTINCT city FROM infprofile WHERE field LIKE $1", [`%${fields}%`]);
        res.json(result.rows);
    } catch (error) {
        console.error("Cities by Field Error:", error);
        res.status(500).json([]);
    }
});

app.post("/api/contact-influencer", isLoggedIn, isCollaborator, (req, res) => {
    const { influencerEmail } = req.body;
    const collaboratorEmail = req.session.user.email;

    let mailOptions = {
        from: process.env.EMAIL_USER,
        to: influencerEmail,
        subject: 'Collaboration Opportunity from promo.com',
        text: `Hello,\n\nA collaborator with the email ${collaboratorEmail} is interested in connecting with you for a potential collaboration.\n\nPlease reach out to them if you are interested.\n\nRegards,\nThe promo.com Team`
    };

    transporter.sendMail(mailOptions, (err) => {
        if (err) {
            console.error('Nodemailer Error:', err);
            return res.status(500).json({ success: false, message: "Failed to send email." });
        }
        res.json({ success: true, message: `Contact request sent to ${influencerEmail}!` });
    });
});


// --- Page Serving ---
app.get("/", (req, res) => res.sendFile(__dirname + "/public/index.html"));
app.get("/adminpage.html", (req, res) => res.sendFile(__dirname + "/public/adminpage.html"));
app.get("/admin-dash.html", isLoggedIn, isAdmin, (req, res) => res.sendFile(__dirname + "/public/admin-dash.html"));
app.get("/admin-users.html", isLoggedIn, isAdmin, (req, res) => res.sendFile(__dirname + "/public/admin-users.html"));
app.get("/admin-all-influ.html", isLoggedIn, isAdmin, (req, res) => res.sendFile(__dirname + "/public/admin-all-influ.html"));
app.get("/infl-dash.html", isLoggedIn, isInfluencer, (req, res) => res.sendFile(__dirname + "/public/infl-dash.html"));
app.get("/inf-profile.html", isLoggedIn, isInfluencer, (req, res) => res.sendFile(__dirname + "/public/inf-profile.html"));
app.get("/infl-events-page.html", isLoggedIn, isInfluencer, (req, res) => res.sendFile(__dirname + "/public/infl-events-page.html"));
app.get("/collaborator-dash.html", isLoggedIn, isCollaborator, (req, res) => res.sendFile(__dirname + "/public/collaborator-dash.html"));
app.get("/coll-profile.html", isLoggedIn, isCollaborator, (req, res) => res.sendFile(__dirname + "/public/coll-profile.html"));
app.get("/infl-finder.html", isLoggedIn, isCollaborator, (req, res) => res.sendFile(__dirname + "/public/infl-finder.html"));


// --- Server Listening ---
const PORT = process.env.PORT || 7485;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});