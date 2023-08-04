const { send } = require('../mail.js');
const User = require('../models/User.js');
const Forgot = require('../models/Forgot.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const uuid = require('uuid');

// @desc POST new mailOrder
// @route POST /mails
// @access Private
const sendOrderMail = async (req, res) => {
  const { email, message } = req.body;
  // Confirm data
  if (!email || !message) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const mail = await send(email, message);

  if (!mail) {
    return res.status(400).json({ message: 'Not created mail' });
  }
  res.json({ mail });
};

// @desc POST send mail with link to user
// @route POST /mails/restore
// @access Public
const checkEmail = async (req, res) => {
  //DB forgots must be empty
  const forgots = await Forgot.find().lean();
  if (forgots.length) {
    await Forgot.deleteMany();
  }

  const { email } = req.body;
  // Confirm data
  if (!email) {
    return res.status(400).json({ message: 'Email field is required' });
  }

  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ message: 'Not found user' });
  }

  const activationLink = uuid.v4();

  const duplicateEmail = await Forgot.find({ email }).lean();
  if (duplicateEmail.length) {
    return res.status(409).json({ message: 'Duplicate email' });
  }
  const date = Date.now();
  const forgotObject = { email, activationLink, date };
  await Forgot.create(forgotObject);

  const message = `<h2>Hello ${email}</h2>
                    <p>Ссылка действительна 10 минут</p>
                    <a href=${process.env.API_URL}/mails/activate/${activationLink}>Перейдите по ссылке</a>`;

  await send(email, message);
  res.json(email);
};

// @desc GET redirect to user site
// @route GET /mails/activate/:link
// @access Public
const activate = async (req, res) => {
  const activationLink = req.params.link;
  const data = await Forgot.findOne({ activationLink }).lean();
  if (data) {
    const aclToken = jwt.sign({ activationLink }, process.env.ACTIVATION_LINK_SECRET, {
      expiresIn: '10m',
    });

    // Create secure cookie with refresh token
    res.cookie('acl', aclToken, {
      httpOnly: true, //accessible only by web server
      secure: true, //https
      sameSite: 'None', //cross-site cookie
      maxAge: 10 * 60 * 1000, //cookie expiry: set to match rT
    });

    return res.redirect(`${process.env.CLIENT_URL}/create`);
  }
  res.status(404).json({ message: 'Not found activation link' });
};

// @desc POST update user with new password
// @route POST /mails/create
// @access Public
const updateUser = async (req, res) => {
  const { password } = req.body;

  // Confirm data
  if (!password) {
    return res.status(400).json({ message: 'Password field are required' });
  }

  const cookies = req.cookies;

  if (!cookies?.acl) return res.status(401).json({ message: 'Not Found ActivationLink cookie' });

  const aclToken = cookies.acl;

  jwt.verify(aclToken, process.env.ACTIVATION_LINK_SECRET, async (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Error decoded acl' });

    const forgot = await Forgot.findOne({
      activationLink: decoded.activationLink,
    }).exec();

    if (!forgot) return res.status(401).json({ message: 'Data of restore password not found' });
    //забрали данные и удаляем запись из DB forgots
    await Forgot.findByIdAndDelete(forgot._id);

    const finishDate = Date.now();
    if (finishDate - forgot.date.getTime() > 600000) {
      return res.status(408).json({
        message: 'Истекло время действия ссылки',
      });
    }
    // Hash password
    const hashedPwd = await bcrypt.hash(password, 10); // salt rounds

    const user = await User.findOneAndUpdate(
      { email: forgot.email },
      {
        email: forgot.email,
        password: hashedPwd,
      },
    );
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден UpdateUser' });
    }
    const accessToken = jwt.sign(
      {
        UserInfo: {
          username: user.username,
          email: user.email,
          roles: user.roles,
          id: user.id,
        },
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '15m' },
    );

    const refreshToken = jwt.sign(
      { username: user.username, email: user.email, id: user.id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' },
    );

    // Create secure cookie with refresh token
    res.cookie('jwt', refreshToken, {
      httpOnly: true, //accessible only by web server
      secure: true, //https
      sameSite: 'None', //cross-site cookie
      maxAge: 7 * 24 * 60 * 60 * 1000, //cookie expiry: set to match rT
    });

    res.json({ accessToken });
  });
};

module.exports = {
  sendOrderMail,
  checkEmail,
  updateUser,
  activate,
};
