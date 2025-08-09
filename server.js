const express = require("express");
const fileuploader = require("express-fileupload");
const mysql2 = require("mysql2");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const session = require("express-session");
require("dotenv").config(); // To load environment variables from .env file

const app = express();
const saltRounds = 10; // For bcrypt password hashing

// --- Middleware ---
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(fileuploader());

// Session Middleware Setup
app.use(session({
    secret: process.env.SESSION_SECRET, // A secret key for signing the session ID cookie
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something stored
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 'secure: true' in production with HTTPS
}));

// --- Database Connection ---
const dbConfig = {
    host: "127.0.0.1",
    user: "root",
    password: "Aryan@113",
    database: "nodeInfluencer",
    dateStrings: true
};

const mysql = mysql2.createConnection(dbConfig);
mysql.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err.stack);
        return;
    }
    console.log("Connected to Database Successfully");
});

// --- Nodemailer Transport ---
let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: "Aryankansal113@gmail.com",
        pass: "Aryan@113"
    }
});

// --- Custom Authentication Middleware ---
const isLoggedIn = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect("/");
    }
    next();
};

const isAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.utype !== 'Admin') {
        return res.status(403).send("Access Forbidden: Admins only.");
    }
    next();
};

const isInfluencer = (req, res, next) => {
    if (!req.session.user || req.session.user.utype !== 'Influencer') {
        return res.status(403).send("Access Forbidden: Influencers only.");
    }
    next();
};

const isCollaborator = (req, res, next) => {
    if (!req.session.user || req.session.user.utype !== 'Collaborator') {
        return res.status(403).send("Access Forbidden: Collaborators only.");
    }
    next();
};

// --- API Routes ---

// USER AUTHENTICATION
app.post("/api/signup", async (req, res) => {
    try {
        const { txtEmail, txtPwd, type } = req.body;
        const hashedPassword = await bcrypt.hash(txtPwd, saltRounds);
        const status = 1;

        mysql.query("INSERT INTO users (email, pwd, utype, status) VALUES (?, ?, ?, ?)", [txtEmail, hashedPassword, type, status], (err) => {
            if (err) {
                console.error("Signup Error:", err);
                return res.status(500).json({ success: false, message: "An account with this email already exists." });
            }
            res.status(201).json({ success: true, message: "Signup successful! Please login." });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: "Server error during signup." });
    }
});

app.post("/api/login", (req, res) => {
    // console.log(req.body);
    const { txtemail, txtpwd } = req.body;
    mysql.query("SELECT * FROM users WHERE email = ?", [txtemail], async (err, result) => {
        if (err || result.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }

        const user = result[0];
        if (user.status === 0) {
            return res.status(403).json({ success: false, message: "Your account is blocked. Please contact support." });
        }

        const passwordMatch = await bcrypt.compare(txtpwd, user.pwd);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }
        
        // Store user info in session
        req.session.user = {
            email: user.email,
            utype: user.utype
        };
        
        res.json({ success: true, message: "Login successful", userType: user.utype });
    });
});

app.post("/api/admin-login", (req, res) => {
    const { adminEmail, adminPass } = req.body;

    mysql.query("SELECT * FROM users WHERE email = ? AND utype = 'Admin'", [adminEmail], async (err, result) => {
        if (err || result.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid admin credentials." });
        }
        
        const admin = result[0];
        const passwordMatch = await bcrypt.compare(adminPass, admin.pwd);

        if (passwordMatch) {
            req.session.user = { email: admin.email, utype: admin.utype };
            res.json({ success: true, message: "Admin login successful." });
        } else {
            res.status(401).json({ success: false, message: "Invalid admin credentials." });
        }
    });
});

app.post("/api/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, message: "Could not log out." });
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.json({ success: true, message: "Logged out successfully." });
    });
});

// Get current user info
app.get("/api/current-user", (req, res) => {
    if (req.session.user) {
        res.json({ success: true, user: req.session.user });
    } else {
        res.status(401).json({ success: false, message: "Not authenticated" });
    }
});

// Password Change
app.put("/api/change-password", isLoggedIn, async (req, res) => {
    const { opwd, npwd } = req.body;
    const email = req.session.user.email;

    mysql.query("SELECT pwd FROM users WHERE email = ?", [email], async (err, result) => {
        if (err || result.length === 0) {
            return res.status(400).json({ success: false, message: "User not found." });
        }

        const passwordMatch = await bcrypt.compare(opwd, result[0].pwd);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, message: "Incorrect old password." });
        }

        const newHashedPassword = await bcrypt.hash(npwd, saltRounds);
        mysql.query("UPDATE users SET pwd = ? WHERE email = ?", [newHashedPassword, email], (err) => {
            if (err) {
                return res.status(500).json({ success: false, message: "Failed to update password." });
            }
            res.json({ success: true, message: "Password changed successfully." });
        });
    });
});

// PROFILE MANAGEMENT
const handleProfileSave = (req, res, table) => {
    let fileName = req.body.hdn || '';
    if (req.files && req.files.ppic) {
        const pic = req.files.ppic;
        fileName = `${Date.now()}-${pic.name}`;
        const uploadPath = `${__dirname}/public/upload/${fileName}`;
        pic.mv(uploadPath, (err) => {
            if (err) return res.status(500).json({ success: false, message: "File upload failed." });
        });
    }
    
    let query, params;
    if (table === 'infprofile') {
        query = "INSERT INTO infprofile VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        params = [req.body.iemail, req.body.txtName, req.body.txtGender, req.body.txtDob, req.body.txtAdd, req.body.txtCity, req.body.txtContact, req.body.txtField.toString(), req.body.txtInsta, req.body.txtYt, req.body.txtOther, fileName];
    } else {
        query = "INSERT INTO coprofile VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        params = [req.body.iemail, req.body.txtName, req.body.txtGender, req.body.txtDob, req.body.txtAdd, req.body.txtCity, req.body.txtContact, req.body.txtInsta, fileName];
    }

    mysql.query(query, params, (err) => {
        if (err) return res.status(500).json({ success: false, message: "Database error: " + err.message });
        res.json({ success: true, message: "Profile saved successfully!" });
    });
};

const handleProfileUpdate = (req, res, table) => {
    let fileName = req.body.hdn || '';
     if (req.files && req.files.ppic) {
        const pic = req.files.ppic;
        fileName = `${Date.now()}-${pic.name}`;
        const uploadPath = `${__dirname}/public/upload/${fileName}`;
        pic.mv(uploadPath, (err) => {
            if (err) return res.status(500).json({ success: false, message: "File upload failed." });
        });
    }

    let query, params;
    if (table === 'infprofile') {
        query = "UPDATE infprofile SET iname=?, gender=?, dob=?, address=?, city=?, contact=?, field=?, insta=?, yt=?, other=?, fileName=? WHERE email=?";
        params = [req.body.txtName, req.body.txtGender, req.body.txtDob, req.body.txtAdd, req.body.txtCity, req.body.txtContact, req.body.txtField.toString(), req.body.txtInsta, req.body.txtYt, req.body.txtOther, fileName, req.body.iemail];
    } else {
        query = "UPDATE coprofile SET iname=?, gender=?, dob=?, address=?, city=?, contact=?, insta=?, fileName=? WHERE email=?";
        params = [req.body.txtName, req.body.txtGender, req.body.txtDob, req.body.txtAdd, req.body.txtCity, req.body.txtContact, req.body.txtInsta, fileName, req.body.iemail];
    }

    mysql.query(query, params, (err) => {
        if (err) return res.status(500).json({ success: false, message: "Database error: " + err.message });
        res.json({ success: true, message: "Profile updated successfully!" });
    });
};

app.post("/api/influencer-profile", isLoggedIn, isInfluencer, (req, res) => handleProfileSave(req, res, 'infprofile'));
app.put("/api/influencer-profile", isLoggedIn, isInfluencer, (req, res) => handleProfileUpdate(req, res, 'infprofile'));
app.post("/api/collaborator-profile", isLoggedIn, isCollaborator, (req, res) => handleProfileSave(req, res, 'coprofile'));
app.put("/api/collaborator-profile", isLoggedIn, isCollaborator, (req, res) => handleProfileUpdate(req, res, 'coprofile'));

app.get("/api/profile/:email", isLoggedIn, (req, res) => {
    const table = req.session.user.utype === 'Influencer' ? 'infprofile' : 'coprofile';
    mysql.query(`SELECT * FROM ${table} WHERE email = ?`, [req.params.email], (err, result) => {
        if (err) return res.status(500).json([]);
        res.json(result);
    });
});

// EVENTS
app.post("/api/events", isLoggedIn, isInfluencer, (req, res) => {
    // console.log(req.body);
    const { btxtname, btxtdate, btime, btxtcity, btxtvenue } = req.body;
    const pemail = req.session.user.email;
    mysql.query("INSERT INTO events (pemail, ename, datee, timing, city, venue) VALUES (?, ?, ?, ?, ?, ?)", [pemail, btxtname, btxtdate, btime, btxtcity, btxtvenue], (err) => {
        if (err) return res.status(500).json({ success: false, message: "Failed to post event." });
        res.json({ success: true, message: "Event posted successfully!" });
    });
});

app.get("/api/events", isLoggedIn, isInfluencer, (req, res) => {
    mysql.query("SELECT * FROM events WHERE pemail = ?", [req.session.user.email], (err, result) => {
        if (err) return res.status(500).json([]);
        res.json(result);
    });
});

app.delete("/api/events/:rid", isLoggedIn, isInfluencer, (req, res) => {
    mysql.query("DELETE FROM events WHERE rid = ? AND pemail = ?", [req.params.rid, req.session.user.email], (err, result) => {
        if (err || result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "Event not found or you don't have permission." });
        }
        res.json({ success: true, message: "Event deleted." });
    });
});

// ADMIN ROUTES
app.get("/api/admin/users", isLoggedIn, isAdmin, (req, res) => {
    mysql.query("SELECT email, pwd, utype, status FROM users", (err, result) => {
        if (err) return res.status(500).json([]);
        res.json(result);
    });
});

app.delete("/api/admin/users/:email", isLoggedIn, isAdmin, (req, res) => {
    const emailToDelete = req.params.email;
    if (emailToDelete === req.session.user.email) {
        return res.status(400).json({ success: false, message: "Admin cannot delete their own account." });
    }
    mysql.query("DELETE FROM users WHERE email = ?", [emailToDelete], (err) => {
        if (err) return res.status(500).json({ success: false, message: "Failed to delete user." });
        res.json({ success: true, message: "User deleted." });
    });
});

app.put("/api/admin/users/:email/status", isLoggedIn, isAdmin, (req, res) => {
    const { status } = req.body; // Expecting status 0 for block, 1 for resume
    const emailToUpdate = req.params.email;
    if (emailToUpdate === req.session.user.email) {
        return res.status(400).json({ success: false, message: "Admin cannot change their own status." });
    }
    mysql.query("UPDATE users SET status = ? WHERE email = ?", [status, emailToUpdate], (err) => {
        if (err) return res.status(500).json({ success: false, message: "Failed to update user status." });
        res.json({ success: true, message: `User status updated.` });
    });
});

app.get("/api/admin/influencer-profiles", isLoggedIn, isAdmin, (req, res) => {
    mysql.query("SELECT * FROM infprofile", (err, result) => {
        if (err) return res.status(500).json([]);
        res.json(result);
    });
});


// INFLUENCER FINDER (for Collaborators)
app.get("/api/influencer-search", isLoggedIn, isCollaborator, (req, res) => {
    let { fields, city, pname } = req.query;
    fields = fields || "";
    city = city || "";
    pname = pname || "";

    let sql = "SELECT * FROM infprofile";
    let conditions = [];
    let params = [];

    if (fields) {
        conditions.push("field LIKE ?");
        params.push(`%${fields}%`);
    }
    if (city) {
        conditions.push("city = ?");
        params.push(city);
    }
    if (pname) {
        conditions.push("iname LIKE ?");
        params.push(`%${pname}%`);
    }

    if (conditions.length > 0) {
        sql += " WHERE " + conditions.join(" AND ");
    }

    mysql.query(sql, params, (err, result) => {
        if (err) return res.status(500).json([]);
        res.json(result);
    });
});

app.get("/api/cities-by-field", isLoggedIn, isCollaborator, (req, res) => {
    const { fields } = req.query;
    mysql.query("SELECT DISTINCT city FROM infprofile WHERE field LIKE ?", [`%${fields}%`], (err, result) => {
        if (err) return res.status(500).json([]);
        res.json(result);
    });
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
// Unprotected routes
app.get("/", (req, res) => res.sendFile(__dirname + "/public/index.html"));
app.get("/adminpage.html", (req, res) => res.sendFile(__dirname + "/public/adminpage.html"));

// Protected routes
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