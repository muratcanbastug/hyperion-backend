const express = require("express");
const router = express.Router();
require("dotenv").config();

const User = require("./../models/User");
const UserOTPVerification = require("./../models/UserOTPVerification");
const PasswordReset = require("./../models/PasswordReset");

// Email handler
const nodemailer = require("nodemailer");

// unique string
const { v4: uuidv4 } = require("uuid");

// Password handler
const bcrypt = require("bcrypt");

let transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    type: "OAuth2",
    user: process.env.AUTH_EMAIL,
    clientId: process.env.AUTH_CLIENT_ID,
    clientSecret: process.env.AUTH_CLIENT_SECRET,
    refreshToken: process.env.AUTH_REFRESH_TOKEN,
  },
});

// Testing transport success
transporter.verify((error, succes) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Server is ready to send messages");
    console.log(succes);
  }
});

// Signup
router.post("/signup", (req, res) => {
  let { userName, email, password } = req.body;
  userName = userName.trim();
  email = email.trim();
  password = password.trim();

  if (userName == "" || email == "" || password == "") {
    res.json({
      status: "FAILED",
      message: "Empty input fields!",
    });
  } else if (!/^[a-zA-Z ]*$/.test(userName)) {
    res.json({
      status: "FAILED",
      message: "Invalid name entered",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "FAILED",
      message: "Invalid email entered",
    });
  } else if (password.length < 8) {
    res.json({
      status: "FAILED",
      message: "Password is too short!",
    });
  } else {
    User.find({ email })
      .then((result) => {
        if (result.length) {
          res.json({
            status: "FAILED",
            message: "User with the provided email already exists",
          });
        } else {
          const saltRounds = 10;
          bcrypt
            .hash(password, saltRounds)
            .then((hashedPassword) => {
              const newUser = new User({
                userName,
                email,
                password: hashedPassword,
                verified: false,
              });

              newUser
                .save()
                .then((result) => {
                  sendOTPVerificationEmail(result, res);
                })
                .catch((err) => {
                  res.json({
                    status: "FAILED",
                    message: "An error occured while saving user account!",
                  });
                });
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occured while hashing password!",
              });
            });
        }
      })
      .catch((err) => {
        console.log(err);
        res.json({
          status: "FAILED",
          message: "An error occured while checking for existing user!",
        });
      });
  }
});

// Send verification email
const sendOTPVerificationEmail = async ({ _id, email, userName }, res) => {
  try {
    const otp = `${Math.floor(1000 + Math.random() * 9000)}`;
    const mailOptions = {
      from: process.env.AUTH_EMAIL,
      to: email,
      subject: "Hyperion Verification",
      html: `<p>Welcome <b>${userName}</b>! Enter <b>${otp}</b> in the app to verify your account and complete the verification.</p>
      <p>This code <b>expires in 1 hour</b>.</p>
      
      <p>If you did not request this, please ignore this email.</p>`,
    };

    const saltRounds = 10;
    const expiresTime = 3600000;

    const hashedOtp = await bcrypt.hash(otp, saltRounds);
    const newOTPVerification = await new UserOTPVerification({
      userId: _id,
      otp: hashedOtp,
      createdAt: Date.now(),
      expiresAt: Date.now() + expiresTime,
    });

    await newOTPVerification.save();
    await transporter.sendMail(mailOptions);

    res.json({
      status: "PENDING",
      message: "Verification OTP email sent",
      data: {
        userId: _id,
        email,
      },
    });
  } catch (err) {
    res.json({
      status: "FAILED",
      message: err.message,
    });
  }
};

// Verification
router.post("/verifyOTP", async (req, res) => {
  try {
    let { userId, otp } = req.body;
    if (!userId || !otp) {
      throw Error("Empty otp details are not allowed");
    } else {
      const UserOTPVerificationRecords = await UserOTPVerification.find({
        userId,
      });
      if (UserOTPVerificationRecords.length <= 0) {
        throw new Error(
          "Account record does not exist or has been verified. Please sign up or log in."
        );
      } else {
        const { expiresAt } = UserOTPVerificationRecords[0];
        const hashedOtp = UserOTPVerificationRecords[0].otp;

        if (expiresAt < Date.now()) {
          await UserOTPVerification.deleteMany({ userId });
          throw new Error("Code has expired. Please try again.");
        } else {
          const validOTP = await bcrypt.compare(otp, hashedOtp);
          if (!validOTP) {
            throw new Error("Invalid code. Check your inbox.");
          } else {
            await User.updateMany({ _id: userId }, { verified: true });
            await UserOTPVerification.deleteMany({ userId });
            res.json({
              status: "VERIFIED",
              message: "User email verified successfully.",
            });
          }
        }
      }
    }
  } catch (err) {
    res.json({
      status: "FAILED",
      message: err.message,
    });
  }
});

router.post("/resendOTPVerificationCode", async (req, res) => {
  try {
    let { userId, email, userName } = req.body;

    if (!userId || !email) {
      throw Error("Empty user details are not allowed");
    } else {
      await UserOTPVerificationCode.deleteMany({ userId });
      sendOTPVerificationEmail({ _id: userId, email, userName }, res);
    }
  } catch (err) {
    res.json({
      status: "FAILED",
      message: err.message,
    });
  }
});

// Password reset
router.post("/requestPasswordReset", async (req, res) => {
  const { email } = req.body;
  if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "FAILED",
      message: "Invalid email entered",
    });
  } else {
    User.find({ email })
      .then((data) => {
        if (data.length > 0) {
          if (!data[0].verified) {
            res.json({
              status: "FAILED",
              message: "Account not verified! Check your inbox.",
            });
          } else {
            PasswordReset.deleteMany({ userId: data[0].id })
              .then(() => sendResetEmail(data[0], res))
              .catch((err) => {
                console.log(err);
                res.json({
                  status: "FAILED",
                  message:
                    "An error occured while deleting password reset request!",
                });
              });
          }
        } else {
          res.json({
            status: "FAILED",
            message: "No account with the suplied email!",
          });
        }
      })
      .catch((err) => {
        console.log(err);
        res.json({
          status: "FAILED",
          message: "An error occurred while checking for existing email",
        });
      });
  }
});

// Reset Password Verification and Update Password
router.post("/resetPassword", async (req, res) => {
  try {
    let { userId, otp, newPassword } = req.body;
    if (!userId || !otp) {
      throw Error("Empty otp details are not allowed");
    } else {
      const ResetPasswordVerificationRecords = await PasswordReset.find({
        userId,
      });
      if (ResetPasswordVerificationRecords.length <= 0) {
        throw new Error("Password reset request not found.");
      } else {
        const { expiresAt } = ResetPasswordVerificationRecords[0];
        const hashedOtp = ResetPasswordVerificationRecords[0].otp;

        if (expiresAt < Date.now()) {
          await PasswordReset.deleteMany({ userId });
          throw new Error("Code has expired. Please try again.");
        } else {
          const validOTP = await bcrypt.compare(otp, hashedOtp);
          if (!validOTP) {
            throw new Error("Invalid code. Check your inbox.");
          } else {
            const saltRounds = 10;
            bcrypt
              .hash(newPassword, saltRounds)
              .then((hashedNewPassword) => {
                User.updateMany(
                  { _id: userId },
                  { password: hashedNewPassword }
                )
                  .then(async () => {
                    await PasswordReset.deleteMany({ userId });
                    res.json({
                      status: "SUCCESS",
                      message: "Password reset successfully.",
                    });
                  })
                  .catch((error) => {
                    console.log(error);
                    res.json({
                      status: "FAILED",
                      message: "An error occured while updating password!",
                    });
                  });
              })
              .catch((error) => {
                console.log(error);
                res.json({
                  status: "FAILED",
                  message: "An error occured while hashing password!",
                });
              });
          }
        }
      }
    }
  } catch (err) {
    res.json({
      status: "FAILED",
      message: err.message,
    });
  }
});

router.post("/resendPasswordResetVerificationCode", async (req, res) => {
  try {
    let { userId, email, userName } = req.body;

    if (!userId || !email) {
      throw Error("Empty user details are not allowed");
    } else {
      await PasswordReset.deleteMany({ userId });
      sendResetEmail({ _id: userId, email, userName }, res);
    }
  } catch (err) {
    res.json({
      status: "FAILED",
      message: err.message,
    });
  }
});

const sendResetEmail = async ({ _id, email, userName }, res) => {
  try {
    const otp = `${Math.floor(1000 + Math.random() * 9000)}`;
    const mailOptions = {
      from: process.env.AUTH_EMAIL,
      to: email,
      subject: "Hyperion Email Reset",
      html: `<p>Hi <b>${userName}</b>! Enter <b>${otp}</b> in the app to reset your password.</p>
      <p>This code <b>expires in 1 hour</b>.</p>
      
      <p>If you did not request this, please ignore this email.</p>`,
    };

    const saltRounds = 10;
    const expiresTime = 3600000;

    const hashedOtp = await bcrypt.hash(otp, saltRounds);
    const newPasswordReset = await new PasswordReset({
      userId: _id,
      otp: hashedOtp,
      createdAt: Date.now(),
      expiresAt: Date.now() + expiresTime,
    });

    await newPasswordReset.save();
    await transporter.sendMail(mailOptions);

    res.json({
      status: "PENDING",
      message: "Reset Pasword email sent",
      data: {
        userId: _id,
        email,
      },
    });
  } catch (err) {
    res.json({
      status: "FAILED",
      message: err.message,
    });
  }
};

// Signin
router.post("/signin", (req, res) => {
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email == "" || password == "") {
    res.json({
      status: "FAILED",
      message: "Empty credentials supplied!",
    });
  } else {
    User.find({ email })
      .then((data) => {
        if (data.length) {
          const hashedPassword = data[0].password;
          bcrypt
            .compare(password, hashedPassword)
            .then((result) => {
              if (result) {
                res.json({
                  status: "SUCCESS",
                  message: "Signin succesful",
                  data: data,
                });
              } else {
                res.json({
                  status: "FAILED",
                  message: "Invalid password entered!",
                });
              }
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occured while comparing password",
              });
            });
        } else {
          res.json({
            status: "FAILED",
            message: "Invalid credentials entered!",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An error occured while checking for existing user",
        });
      });
  }
});

module.exports = router;
