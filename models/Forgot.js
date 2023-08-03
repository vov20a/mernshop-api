const { Schema, model } = require('mongoose');

const ForgotSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  activationLink: {
    type: String,
    required: true,
    unique: true,
  },
  date: {
    type: Date,
    required: true,
    unique: true,
  },
});

module.exports = model('Forgot', ForgotSchema);
