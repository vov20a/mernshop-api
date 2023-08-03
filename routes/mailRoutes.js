const express = require('express');
const router = express.Router();
const mailsController = require('../controllers/mailsController');
const verifyJWT = require('../middlewares/verifyJWT');

router.route('/restore').post(mailsController.checkEmail);
router.route('/create').post(mailsController.updateUser);
router.route('/activate/:link').get( mailsController.activate);

router.use(verifyJWT);
router.route('/').post(mailsController.sendOrderMail);

module.exports = router;
