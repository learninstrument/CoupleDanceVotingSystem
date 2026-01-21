require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const multer = require('multer'); // For video uploads
const axios = require('axios');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('trust proxy', 1); // Required for sessions to work correctly on cPanel/Whogohost

// Session Setup
const sessionStore = new MySQLStore({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

app.use(session({
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false
}));

// Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL Database');

    // Create Settings Table if not exists
    const createSettingsTable = `CREATE TABLE IF NOT EXISTS settings (
        setting_key VARCHAR(50) PRIMARY KEY,
        setting_value VARCHAR(255)
    )`;
    db.query(createSettingsTable, (err) => {
        if (err) console.error(err);
        db.query("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('registration_fee', '6000')", (err) => {});
    });
});

// Multer Setup for Video Uploads
const storage = multer.diskStorage({
    destination: path.join(__dirname, 'public', 'uploads'),
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// Email Configuration
const emailUser = process.env.EMAIL_USER || '';
const isLocalDomain = emailUser.includes('coupledance.com.ng');
const smtpHost = process.env.SMTP_HOST || (isLocalDomain ? 'localhost' : 'smtp.gmail.com');
const smtpPort = process.env.SMTP_PORT || (isLocalDomain ? 465 : 587);
const isSecure = process.env.SMTP_SECURE === 'true' || smtpPort == 465;

const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: isSecure,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    }
});
console.log(`📧 Email Config: Host=${smtpHost}, Port=${smtpPort}, Secure=${isSecure}`);

// --- ROUTES ---

// 1. Home Page (Public Viewing)
app.get('/', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 9;
    const offset = (page - 1) * limit;

    let baseSql = `FROM contestants c JOIN users u ON c.user_id = u.id`;
    let whereClause = "";

    const params = [];
    if (req.query.search) {
        whereClause = " WHERE u.username LIKE ?";
        params.push('%' + req.query.search + '%');
    }

    // Count Query
    let countSql = `SELECT COUNT(*) as count ${baseSql} ${whereClause}`;

    // Data Query
    let dataSql = `SELECT c.*, u.username, u.social_media_handle,
                 (SELECT IFNULL(SUM(number_of_votes), 0) FROM votes WHERE contestant_id = c.id) as total_votes 
                 ${baseSql} ${whereClause}`;

    // Sorting Logic
    let sortOrder = "total_votes DESC"; // Default
    if (req.query.sort === 'newest') {
        sortOrder = "c.id DESC";
    }

    dataSql += ` ORDER BY ${sortOrder} LIMIT ? OFFSET ?`;

    db.query(countSql, params, (err, countResult) => {
        if (err) throw err;
        const totalContestants = countResult[0].count;
        const totalPages = Math.ceil(totalContestants / limit);

        db.query(dataSql, [...params, limit, offset], (err, results) => {
            if (err) throw err;
            res.render('index', { 
                contestants: results, 
                user: req.session.user, 
                searchQuery: req.query.search,
                currentSort: req.query.sort || 'most_voted',
                currentPage: page,
                totalPages: totalPages
            });
        });
    });
});

// 2. Authentication (Register & Login)
app.get('/login', (req, res) => res.render('login', { error: null }));
app.get('/register', (req, res) => {
    db.query("SELECT setting_value FROM settings WHERE setting_key = 'registration_fee'", (err, results) => {
        const registrationFee = results.length > 0 ? results[0].setting_value : '6000';
        res.render('register', { registrationFee, error: null });
    });
});

app.post('/register', async (req, res) => {
    const { username, email, password, referred_by, social_media_handle, phone_number } = req.body;

    // 1. Check if email already exists in DB
    db.query('SELECT id FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) { console.error(err); return res.send("Error checking user"); }
        if (results.length > 0) {
             db.query("SELECT setting_value FROM settings WHERE setting_key = 'registration_fee'", (err, settingsResults) => {
                const registrationFee = settingsResults.length > 0 ? settingsResults[0].setting_value : '6000';
                return res.render('register', { registrationFee, error: "This email is already registered. Please <a href='/login'>Login</a>." });
             });
             return;
        }

        // 2. Prepare Data (Do not insert yet)
        const hashedPassword = await bcrypt.hash(password, 10);
        const referralCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        const referrer = referred_by ? referred_by : null;
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        console.log(`Verification Code for ${email}: ${verificationCode}`);

        // 3. Store in Session
        req.session.pendingUser = {
            username, email, password: hashedPassword, referralCode, referrer, verificationCode,
            is_contestant: req.body.is_contestant ? true : false,
            social_media_handle, phone_number
        };

        // 4. Send Email
        const logoUrl = `http://${req.headers.host}/images/logo.png`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify your Email - Love in Motion',
            html: `
                <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f4f4f4; padding: 20px;">
                    <div style="background: linear-gradient(135deg, #421746, #a98213); padding: 30px 20px; text-align: center; border-radius: 10px 10px 0 0;">
                        <img src="${logoUrl}" alt="Love in Motion" style="max-width: 80px; margin-bottom: 15px;">
                        <h1 style="color: white; margin: 0; font-size: 24px; text-transform: uppercase;">Love in Motion</h1>
                    </div>
                    <div style="background-color: white; padding: 40px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        <h2 style="color: #421746; text-align: center; margin-top: 0;">Verify Your Email</h2>
                        <p style="font-size: 16px; color: #555; text-align: center; line-height: 1.5;">Welcome to the competition! To complete your registration, please use the verification code below.</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <span style="display: inline-block; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #a98213; background-color: #fff8e1; padding: 15px 40px; border-radius: 5px; border: 2px dashed #a98213;">${verificationCode}</span>
                        </div>
                        <p style="font-size: 14px; color: #888; text-align: center;">If you didn't request this, simply ignore this email.</p>
                    </div>
                    <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
                        &copy; ${new Date().getFullYear()} Love in Motion. All rights reserved.
                    </div>
                </div>
            `
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("❌ Error sending registration email:", error);
                if (error.code === 'ESOCKET') console.error("💡 TIP: If on Localhost, disable Antivirus. If on Hosting, set SMTP_HOST to 'localhost'.");
            } else {
                console.log("✅ Registration email sent successfully:", info.response);
            }
        });

        req.session.save((err) => {
            if (err) console.error("Session save error:", err);
            res.redirect('/verify');
        });
    });
});

app.get('/verify', (req, res) => {
    if (!req.session.pendingUser) return res.redirect('/register');
    
    const email = req.session.pendingUser.email;
    const resent = req.query.resent === 'true';
    res.render('verify', { email: email, resent });
});

app.post('/verify', (req, res) => {
    const { code } = req.body;
    const pendingUser = req.session.pendingUser;

    if (!pendingUser) return res.send("Session expired or invalid. Please register again.");

    if (pendingUser.verificationCode === code) {
        // Code matches! Now we insert into DB.

        // Update referrer count (only for verified users)
        if (pendingUser.referrer) {
            db.query('UPDATE users SET referral_count = referral_count + 1 WHERE referral_code = ?', [pendingUser.referrer]);
        }

        const sql = 'INSERT INTO users (username, email, password, referral_code, referred_by, verification_code, is_verified, social_media_handle, phone_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
        // We insert NULL for verification_code and TRUE for is_verified
        db.query(sql, [pendingUser.username, pendingUser.email, pendingUser.password, pendingUser.referralCode, pendingUser.referrer, null, true, pendingUser.social_media_handle, pendingUser.phone_number], async (err, result) => {
            if (err) { console.error(err); return res.send("Error creating account"); }

            const userId = result.insertId;
            const isContestant = pendingUser.is_contestant;
            const email = pendingUser.email;

            // Clear session
            delete req.session.pendingUser;

            // Log user in immediately so session exists during payment
            req.session.user = {
                id: userId,
                username: pendingUser.username,
                email: pendingUser.email,
                referral_code: pendingUser.referralCode,
                phone_number: pendingUser.phone_number,
                social_media_handle: pendingUser.social_media_handle,
                profile_pic: null
            };

            // Save session before redirecting to ensure user stays logged in
            req.session.save((err) => {
                if (isContestant) {
                    db.query("SELECT setting_value FROM settings WHERE setting_key = 'registration_fee'", async (err, settingsResults) => {
                        const fee = settingsResults.length > 0 ? parseInt(settingsResults[0].setting_value) : 6000;
                        try {
                            const callbackUrl = `http://${req.headers.host}/paystack/callback`;
                            const response = await axios.post('https://api.paystack.co/transaction/initialize', {
                                email: email,
                                amount: fee * 100,
                                callback_url: callbackUrl,
                                metadata: { user_id: userId, purpose: 'registration' }
                            }, { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } });
                            
                            const { authorization_url, reference } = response.data.data;
                            db.query('INSERT INTO transactions (user_id, reference, amount, purpose, status) VALUES (?, ?, ?, ?, ?)', 
                                [userId, reference, fee, 'registration', 'pending'], (err) => {
                                    if (err) console.error("Pending Transaction Log Error:", err);
                                    res.redirect(authorization_url);
                                });
                        } catch (error) {
                            console.error(error);
                            res.send("Error initializing payment");
                        }
                    });
                } else {
                    res.redirect('/login');
                }
            });
        });
    } else {
        res.send("Invalid Code");
    }
});

app.post('/resend-code', (req, res) => {
    if (!req.session.pendingUser) return res.redirect('/register');

    const email = req.session.pendingUser.email;
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Update session with new code
    req.session.pendingUser.verificationCode = verificationCode;

    const logoUrl = `http://${req.headers.host}/images/logo.png`;
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'New Verification Code - Love in Motion',
        html: `
            <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f4f4f4; padding: 20px;">
                <div style="background: linear-gradient(135deg, #421746, #a98213); padding: 30px 20px; text-align: center; border-radius: 10px 10px 0 0;">
                    <img src="${logoUrl}" alt="Love in Motion" style="max-width: 80px; margin-bottom: 15px;">
                    <h1 style="color: white; margin: 0; font-size: 24px; text-transform: uppercase;">Love in Motion</h1>
                </div>
                <div style="background-color: white; padding: 40px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #421746; text-align: center; margin-top: 0;">New Verification Code</h2>
                    <p style="font-size: 16px; color: #555; text-align: center; line-height: 1.5;">You requested a new verification code. Please use the code below to complete your registration.</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <span style="display: inline-block; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #a98213; background-color: #fff8e1; padding: 15px 40px; border-radius: 5px; border: 2px dashed #a98213;">${verificationCode}</span>
                    </div>
                    <p style="font-size: 14px; color: #888; text-align: center;">If you didn't request this, simply ignore this email.</p>
                </div>
                <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
                    &copy; ${new Date().getFullYear()} Love in Motion. All rights reserved.
                </div>
            `
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("❌ Error resending code:", error);
            if (error.code === 'ESOCKET') console.error("💡 TIP: If on Localhost, disable Antivirus. If on Hosting, set SMTP_HOST to 'localhost'.");
        } else {
            console.log("✅ Resend code email sent successfully:", info.response);
        }
        req.session.save((err) => {
            if (err) console.error("Session save error:", err);
            res.redirect('/verify?resent=true');
        });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (results.length === 0 || !(await bcrypt.compare(password, results[0].password))) {
            return res.render('login', { error: "Invalid email or password. Please try again." });
        }
        req.session.user = results[0];
        res.redirect('/dashboard');
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) console.log(err);
        res.redirect('/login');
    });
});

// Forgot Password Routes
app.get('/forgot-password', (req, res) => res.render('forgot-password'));

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) { console.error(err); return res.send("Error looking up user"); }
        
        if (results.length === 0) {
            // For security, we usually don't tell if the email exists, but for now:
            return res.send('If an account with that email exists, a reset link has been sent.');
        }
        
        const user = results[0];
        const token = crypto.randomBytes(20).toString('hex');
        const expires = Date.now() + 3600000; // 1 hour from now

        db.query('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?', [token, expires, user.id], (err) => {
            if (err) throw err;

            const resetLink = `http://${req.headers.host}/reset-password/${token}`;
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Password Reset Request',
                text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
                      `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
                      `${resetLink}\n\n` +
                      `If you did not request this, please ignore this email and your password will remain unchanged.\n`
            };

            transporter.sendMail(mailOptions, (error) => {
                if (error) { console.log(error); return res.send("Error sending email"); }
                res.send('Password reset link sent to your email.');
            });
        });
    });
});

app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    db.query('SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?', [token, Date.now()], (err, results) => {
        if (results.length === 0) return res.send('Password reset token is invalid or has expired.');
        res.render('reset-password', { token });
    });
});

app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE reset_token = ? AND reset_token_expires > ?', [hashedPassword, token, Date.now()], (err, result) => {
        if (err) throw err;
        res.send('Success! Your password has been changed. <a href="/login">Login here</a>.');
    });
});

// 3. Dashboard
app.get('/dashboard', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    
    // Check if user is already a contestant
    db.query('SELECT * FROM contestants WHERE user_id = ?', [req.session.user.id], (err, results) => {
        if (err) throw err;
        const isContestant = results.length > 0;
        const contestant = isContestant ? results[0] : null;

        // Check if user has paid (successful registration transaction)
        db.query("SELECT * FROM transactions WHERE user_id = ? AND purpose = 'registration' ORDER BY id DESC LIMIT 1", [req.session.user.id], (err, transResults) => {
            if (err) throw err;
            const latestTrans = transResults.length > 0 ? transResults[0] : null;
            const hasPaid = latestTrans && latestTrans.status === 'success';
            const pendingRef = (latestTrans && latestTrans.status === 'pending') ? latestTrans.reference : null;
            
            // Fetch referrals (users who registered with this user's referral code)
            db.query('SELECT username FROM users WHERE referred_by = ?', [req.session.user.referral_code], (err, referralResults) => {
                if (err) throw err;
                const referrals = referralResults;

                if (isContestant) {
                    // Fetch voters for this contestant
                    const sql = `SELECT u.username, v.number_of_votes, v.created_at 
                                 FROM votes v 
                                 JOIN users u ON v.voter_id = u.id 
                                 WHERE v.contestant_id = ? 
                                 ORDER BY v.created_at DESC`;
                    
                    db.query(sql, [contestant.id], (err, voteResults) => {
                        if (err) throw err;
                        const totalVotes = voteResults.reduce((sum, v) => sum + v.number_of_votes, 0);
                        
                        db.query("SELECT setting_value FROM settings WHERE setting_key = 'registration_fee'", (err, settingsResults) => {
                            const registrationFee = settingsResults.length > 0 ? settingsResults[0].setting_value : '6000';
                            res.render('dashboard', { user: req.session.user, isContestant, hasPaid, voters: voteResults, totalVotes, contestant, referrals, registrationFee, pendingRef });
                        });
                    });
                } else {
                    db.query("SELECT setting_value FROM settings WHERE setting_key = 'registration_fee'", (err, settingsResults) => {
                        const registrationFee = settingsResults.length > 0 ? settingsResults[0].setting_value : '6000';
                        res.render('dashboard', { user: req.session.user, isContestant, hasPaid, voters: [], totalVotes: 0, contestant: null, referrals, registrationFee, pendingRef });
                    });
                }
            });
        });
    });
});

// 4. Paystack Integration (Initialize Payment)
app.post('/pay', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    
    const { amount, email, purpose, contestant_id } = req.body; 
    // Note: Amount in Paystack is in Kobo (multiply Naira by 100)
    
    try {
        const callbackUrl = `http://${req.headers.host}/paystack/callback`;

        const response = await axios.post('https://api.paystack.co/transaction/initialize', {
            email: email,
            amount: amount * 100, 
            callback_url: callbackUrl,
            metadata: {
                user_id: req.session.user.id,
                purpose: purpose, // 'registration' or 'vote'
                contestant_id: contestant_id || null
            }
        }, {
            headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
        });

        const { authorization_url, reference } = response.data.data;

        // Log Pending Transaction immediately so we have the reference
        db.query('INSERT INTO transactions (user_id, reference, amount, purpose, status) VALUES (?, ?, ?, ?, ?)', 
            [req.session.user.id, reference, amount, purpose, 'pending'], (err) => {
                if (err) console.error("Pending Transaction Log Error:", err);
                res.redirect(authorization_url);
            });
    } catch (error) {
        console.error(error);
        res.send("Payment Initialization Failed");
    }
});

// 5. Paystack Callback (Verify Payment)
app.get('/paystack/callback', async (req, res) => {
    const reference = req.query.reference;
    console.log(`Verifying Paystack Reference: ${reference}`);

    try {
        const verify = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, {
            headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
        });

        const data = verify.data.data;
        if (data.status === 'success') {
            const { user_id, purpose, contestant_id } = data.metadata;
            const amountPaid = data.amount / 100;

            // Log Transaction
            // Use ON DUPLICATE KEY UPDATE to update the 'pending' transaction to 'success'
            const sql = `INSERT INTO transactions (user_id, reference, amount, purpose, status) VALUES (?, ?, ?, ?, 'success') ON DUPLICATE KEY UPDATE status='success'`;
            db.query(sql, [user_id, reference, amountPaid, purpose], (err) => {
                if (err) console.error("Transaction Log Error:", err);

                    if (purpose === 'registration') {
                        // Allow user to upload video now (Redirect to upload page)
                        req.session.isPaidContestant = true; 
                        
                        // If user is not logged in (e.g. paid during registration), log them in
                        if (!req.session.user) {
                            db.query('SELECT * FROM users WHERE id = ?', [user_id], (err, results) => {
                                if (!err && results.length > 0) {
                                    req.session.user = results[0];
                                    req.session.save(() => {
                                        res.redirect('/dashboard');
                                    });
                                } else {
                                    res.redirect('/login');
                                }
                            });
                        } else {
                            req.session.save(() => {
                                res.redirect('/dashboard');
                            });
                        }
                    } else if (purpose === 'vote') {
                        // Calculate votes (e.g., 100 Naira = 1 Vote)
                        const votesToAdd = Math.floor(amountPaid / 100); 
                        
                        db.query('INSERT INTO votes (contestant_id, voter_id, number_of_votes, created_at) VALUES (?, ?, ?, NOW())', 
                            [contestant_id, user_id, votesToAdd], (err) => {
                                if (err) console.error("Vote Log Error:", err);
                                res.redirect('/');
                            });
                    } else {
                        // Fallback: Redirect to home if purpose is undefined or unknown
                        res.redirect('/');
                    }
            });
        } else {
            res.send("Payment Verification Failed");
        }
    } catch (error) {
        console.error(error);
        res.send("Error Verifying Payment");
    }
});

// 5b. Manual Payment Check
app.post('/check-payment-status', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const { reference } = req.body;

    try {
        const verify = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, {
            headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
        });

        if (verify.data.data.status === 'success') {
            db.query("UPDATE transactions SET status = 'success' WHERE reference = ?", [reference], (err) => {
                if (err) console.error(err);
                res.redirect('/dashboard');
            });
        } else {
            res.redirect('/dashboard');
        }
    } catch (error) {
        console.error(error);
        res.redirect('/dashboard');
    }
});

// 6. Video Upload (Only after payment)
app.get('/upload-video', (req, res) => {
    // In production, verify transaction in DB here before rendering
    res.render('upload');
});

app.post('/upload-video', upload.single('video'), (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    
    if (!req.file) {
        return res.send("Error: No video selected or file upload failed.");
    }

    const { description } = req.body;
    const filename = req.file.filename;

    // Check if contestant record already exists
    db.query('SELECT id FROM contestants WHERE user_id = ?', [req.session.user.id], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            // Update existing record
            db.query('UPDATE contestants SET video_filename = ?, description = ? WHERE user_id = ?', 
                [filename, description, req.session.user.id], (err) => {
                    if (err) throw err;
                    res.redirect('/dashboard');
            });
        } else {
            // Insert new record
            db.query('INSERT INTO contestants (user_id, video_filename, description) VALUES (?, ?, ?)', 
                [req.session.user.id, filename, description], (err) => {
                    if (err) throw err;
                    res.redirect('/dashboard');
            });
        }
    });
});

// 7. Profile Picture Upload
app.post('/upload-profile-pic', upload.single('profile_pic'), (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    
    if (!req.file) {
        return res.send("Error: No file selected.");
    }

    const filename = req.file.filename;

    db.query('UPDATE users SET profile_pic = ? WHERE id = ?', [filename, req.session.user.id], (err) => {
        if (err) throw err;
        // Update session so the image shows up immediately without re-login
        req.session.user.profile_pic = filename;
        res.redirect('/dashboard');
    });
});

// 8. Admin Dashboard
app.get('/admin', (req, res) => {
    // 1. Security: Check if logged in and if email matches Admin Email
    // REPLACE 'admin@gmail.com' with the specific email address you want to use as admin
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL; 
    
    if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) {
        return res.status(403).send(`Access Denied.`);
    }

    // 2. Fetch Data
    // Query A: Users and Payment Status (Check if they paid 6000 for registration)
    const usersSql = `
        SELECT u.*, 
        (SELECT COUNT(*) FROM transactions t WHERE t.user_id = u.id AND t.purpose = 'registration' AND t.status = 'success') as has_paid,
        (SELECT reference FROM transactions t WHERE t.user_id = u.id AND t.purpose = 'registration' AND t.status = 'success' LIMIT 1) as payment_reference,
        c.video_filename,
        c.id as contestant_id
        FROM users u
        LEFT JOIN contestants c ON u.id = c.user_id
        ORDER BY u.id DESC
    `;

    // Query B: Votes Log (Who voted for whom)
    const votesSql = `
        SELECT v.*, 
               voter.username as voter_name, 
               voter.email as voter_email,
               voter.phone_number as voter_phone,
               c_user.username as contestant_name 
        FROM votes v 
        JOIN users voter ON v.voter_id = voter.id 
        JOIN contestants c ON v.contestant_id = c.id 
        JOIN users c_user ON c.user_id = c_user.id
        ORDER BY v.created_at DESC
    `;

    // Query C: General Stats
    const statsSql = `
        SELECT 
            (SELECT COUNT(*) FROM contestants) as total_contestants,
            (SELECT IFNULL(SUM(amount), 0) FROM transactions WHERE status='success') as total_revenue,
            (SELECT COUNT(*) FROM users) as total_users,
            (SELECT IFNULL(SUM(number_of_votes), 0) FROM votes) as total_votes,
            (SELECT COUNT(*) FROM transactions WHERE purpose='registration' AND status='success') as total_registrations,
            (SELECT IFNULL(SUM(amount), 0) FROM transactions WHERE purpose='vote' AND status='success') as total_vote_revenue,
            (SELECT IFNULL(SUM(amount), 0) FROM transactions WHERE purpose='registration' AND status='success') as total_registration_revenue
    `;

    // Query D: Top Contestant
    const topContestantSql = `
        SELECT c.id, u.username, SUM(v.number_of_votes) as total_votes
        FROM contestants c
        JOIN users u ON c.user_id = u.id
        JOIN votes v ON c.id = v.contestant_id
        GROUP BY c.id
        ORDER BY total_votes DESC
        LIMIT 1
    `;

    // Query F: Lowest Contestant
    const lowestContestantSql = `
        SELECT c.id, u.username, IFNULL(SUM(v.number_of_votes), 0) as total_votes
        FROM contestants c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN votes v ON c.id = v.contestant_id
        GROUP BY c.id
        ORDER BY total_votes ASC
        LIMIT 1
    `;

    // Query E: Chart Data (Votes per day)
    const chartSql = `
        SELECT DATE_FORMAT(created_at, '%Y-%m-%d') as date, SUM(number_of_votes) as count 
        FROM votes 
        GROUP BY date 
        ORDER BY date ASC
    `;

    // Query G: Referral Network
    const referralSql = `
        SELECT 
            r.id as referrer_id, r.username as referrer_name, r.email as referrer_email, r.phone_number as referrer_phone, r.referral_code,
            u.id as referee_id, u.username as referee_name, u.email as referee_email, u.phone_number as referee_phone, u.social_media_handle as referee_social, u.created_at as referee_joined,
            (SELECT COUNT(*) FROM transactions t WHERE t.user_id = u.id AND t.purpose = 'registration' AND t.status = 'success') as referee_paid
        FROM users r
        JOIN users u ON u.referred_by = r.referral_code
        ORDER BY r.id DESC, u.created_at DESC
    `;

    // Query H: All Transactions (For tracking)
    let transactionsSql = `
        SELECT t.*, u.username, u.email 
        FROM transactions t 
        LEFT JOIN users u ON t.user_id = u.id 
        WHERE 1=1
    `;
    const transactionParams = [];
    if (req.query.trans_status) {
        transactionsSql += ` AND t.status = ?`;
        transactionParams.push(req.query.trans_status);
    }
    if (req.query.trans_search) {
        transactionsSql += ` AND (t.reference LIKE ? OR u.email LIKE ?)`;
        transactionParams.push(`%${req.query.trans_search}%`, `%${req.query.trans_search}%`);
    }
    transactionsSql += ` ORDER BY t.id DESC LIMIT 100`;

    db.query(usersSql, (err, users) => {
        if (err) throw err;
        db.query(votesSql, (err, votes) => {
            if (err) throw err;
            db.query(statsSql, (err, statsResults) => {
                if (err) throw err;
                
                db.query(chartSql, (err, chartResults) => {
                    if (err) throw err;

                    db.query(referralSql, (err, referralResults) => {
                        if (err) throw err;

                        // Process Referrals
                        const referralsMap = {};
                        referralResults.forEach(row => {
                            if (!referralsMap[row.referrer_id]) {
                                referralsMap[row.referrer_id] = {
                                    id: row.referrer_id,
                                    name: row.referrer_name,
                                    email: row.referrer_email,
                                    phone: row.referrer_phone,
                                    code: row.referral_code,
                                    referees: []
                                };
                            }
                            referralsMap[row.referrer_id].referees.push({
                                id: row.referee_id,
                                name: row.referee_name,
                                email: row.referee_email,
                                phone: row.referee_phone,
                                social: row.referee_social,
                                joined: row.referee_joined,
                                paid: row.referee_paid
                            });
                        });
                        const referrals = Object.values(referralsMap);

                        db.query(topContestantSql, (err, topContestantResult) => {
                            if (err) throw err;
                            const topContestant = topContestantResult.length > 0 ? topContestantResult[0] : null;

                            db.query(lowestContestantSql, (err, lowestResult) => {
                                if (err) throw err;
                                const lowestContestant = lowestResult.length > 0 ? lowestResult[0] : null;

                                if (topContestant) {
                                    const topVoterSql = `
                                        SELECT u.username, SUM(v.number_of_votes) as votes_given
                                        FROM votes v
                                        JOIN users u ON v.voter_id = u.id
                                        WHERE v.contestant_id = ?
                                        GROUP BY v.voter_id
                                        ORDER BY votes_given DESC
                                        LIMIT 1
                                    `;
                                    db.query(topVoterSql, [topContestant.id], (err, topVoterResult) => {
                                        if (err) throw err;
                                        const topVoter = topVoterResult.length > 0 ? topVoterResult[0] : null;
                                        db.query(transactionsSql, transactionParams, (err, transactions) => {
                                            if (err) throw err;
                                            db.query("SELECT setting_value FROM settings WHERE setting_key = 'registration_fee'", (err, settingsResults) => {
                                                const registrationFee = settingsResults.length > 0 ? settingsResults[0].setting_value : '6000';
                                                res.render('admin', { 
                                                    users, votes, stats: statsResults[0], user: req.session.user,
                                                    topContestant, topVoter, lowestContestant, chartData: chartResults,
                                                    referrals, registrationFee, transactions,
                                                    transSearch: req.query.trans_search,
                                                    transStatus: req.query.trans_status
                                                });
                                            });
                                        });
                                    });
                                } else {
                                    db.query(transactionsSql, transactionParams, (err, transactions) => {
                                        db.query("SELECT setting_value FROM settings WHERE setting_key = 'registration_fee'", (err, settingsResults) => {
                                            const registrationFee = settingsResults.length > 0 ? settingsResults[0].setting_value : '6000';
                                            res.render('admin', { 
                                                users, votes, stats: statsResults[0], user: req.session.user,
                                                topContestant: null, topVoter: null, lowestContestant, chartData: chartResults,
                                                referrals, registrationFee, transactions,
                                                transSearch: req.query.trans_search,
                                                transStatus: req.query.trans_status
                                            });
                                        });
                                    });
                                }
                            });
                        });
                    });
                });
            });
        });
    });
});

app.post('/admin/update-settings', (req, res) => {
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL; 
    if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) {
        return res.status(403).send(`Access Denied.`);
    }
    const { registration_fee } = req.body;
    db.query("UPDATE settings SET setting_value = ? WHERE setting_key = 'registration_fee'", [registration_fee], (err) => {
        if (err) console.error(err);
        res.redirect('/admin');
    });
});

// 9. Admin Actions (Delete User/Video)
app.post('/admin/delete-user', (req, res) => {
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL; 
    if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) {
        return res.status(403).send(`Access Denied.`);
    }

    const userId = req.body.user_id;

    // Delete related data first to avoid foreign key constraint errors
    // 1. Get contestant ID if exists
    db.query('SELECT id FROM contestants WHERE user_id = ?', [userId], (err, results) => {
        
        const deleteUser = () => {
             db.query('DELETE FROM users WHERE id = ?', [userId], (err) => {
                if (err) console.error(err);
                res.redirect('/admin');
            });
        };

        const deleteContestant = () => {
            db.query('DELETE FROM contestants WHERE user_id = ?', [userId], (err) => {
                if(err) console.error(err);
                deleteUser();
            });
        };

        const deleteTransactions = () => {
             db.query('DELETE FROM transactions WHERE user_id = ?', [userId], (err) => {
                if(err) console.error(err);
                deleteContestant();
             });
        };
        
        const deleteVotesVoter = () => {
            db.query('DELETE FROM votes WHERE voter_id = ?', [userId], (err) => {
                if(err) console.error(err);
                deleteTransactions();
            });
        };

        if (!err && results.length > 0) {
            const contestantId = results[0].id;
            // Delete votes received by this contestant
            db.query('DELETE FROM votes WHERE contestant_id = ?', [contestantId], (err) => {
                if(err) console.error(err);
                deleteVotesVoter();
            });
        } else {
            deleteVotesVoter();
        }
    });
});

app.post('/admin/delete-video', (req, res) => {
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL; 
    if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) {
        return res.status(403).send(`Access Denied.`);
    }

    const userId = req.body.user_id;
    
    // 1. Get contestant ID to delete votes first
    db.query('SELECT id FROM contestants WHERE user_id = ?', [userId], (err, results) => {
        if (err) { console.error(err); return res.redirect('/admin'); }
        
        const deleteContestant = () => {
            db.query('DELETE FROM contestants WHERE user_id = ?', [userId], (err) => {
                if (err) console.error(err);
                res.redirect('/admin');
            });
        };

        if (results.length > 0) {
            db.query('DELETE FROM votes WHERE contestant_id = ?', [results[0].id], (err) => {
                if (err) console.error(err);
                deleteContestant();
            });
        } else {
            deleteContestant();
        }
    });
});

// 11. Delete Transaction (Admin Action)
app.post('/admin/delete-transaction', (req, res) => {
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL; 
    if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) {
        return res.status(403).send(`Access Denied.`);
    }
    const { transaction_id } = req.body;
    db.query('DELETE FROM transactions WHERE id = ?', [transaction_id], (err) => {
        if (err) console.error(err);
        res.redirect('/admin#transactions-section');
    });
});

// 10. Delete Video (User Action)
app.post('/delete-video', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    // Get the video filename first to delete from storage
    db.query('SELECT id, video_filename FROM contestants WHERE user_id = ?', [req.session.user.id], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            const filename = results[0].video_filename;
            const contestantId = results[0].id;
            const filePath = path.join(__dirname, 'public', 'uploads', filename);

            // 1. Delete votes associated with this contestant first
            db.query('DELETE FROM votes WHERE contestant_id = ?', [contestantId], (err) => {
                if (err) throw err;

                // 2. Delete record from DB
                db.query('DELETE FROM contestants WHERE user_id = ?', [req.session.user.id], (err) => {
                    if (err) throw err;
                    // 3. Delete file from disk
                    fs.unlink(filePath, (err) => { if (err) console.error("File deletion error:", err); });
                    res.redirect('/dashboard');
                });
            });
        } else {
            res.redirect('/dashboard');
        }
    });
});

app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});
