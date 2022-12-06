const nodemailer = require("nodemailer");
const transporter = require("./nodemailerConfig");

const sendEmail = async ({ to, subject, html }) => {
  let testAccount = await nodemailer.createTestAccount();

  return transporter.sendMail({
    from: '"Ayush Gupta" <ayush@gmail.com>', // sender address
    to: to, // list of receivers
    subject: subject, // Subject line
    html: html, // html body
  });
};

module.exports = sendEmail;
