const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

let transporter = nodemailer.createTransport({
  // host: 'smtp.mail.ru',
  // port: 465,
  // secure: true, // true for 465, false for other ports
  // auth: {
  //   user: process.env.EMAIL_HOST_USER,
  //   pass: process.env.EMAIL_HOST_PASSWORD, // generated email password
  // },
  secure: false,
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
});

async function send(receiver, message) {
  try {
    const info = await transporter.sendMail({
      //'from' the same as 'auth.user'
      from: 'alexeevvova1960@gmail.com',
      to: receiver,
      subject: 'Mern-Shopper',
      text: message,
      html: `<b>${message}</b>`,
    });
    return info.messageId;
  } catch (e) {
    return { error: e };
  }
}

module.exports = { send };
