const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.ethereal.email",
  port: 587,
  auth: {
    user: "betty.feil28@ethereal.email",
    pass: "Ec2b9u7qeaN6gyppNb",
  },
});

module.exports = transporter;
