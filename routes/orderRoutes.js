const express = require('express');
const router = express.Router();
const ordersController = require('../controllers/ordersController');
const verifyJWT = require('../middlewares/verifyJWT');

router.use(verifyJWT);

router.route('/:userId').get(ordersController.getOrdersByUserId);

router
  .route('/')
  .get(ordersController.getAllOrders)
  .post(ordersController.createNewOrder)
  .patch(ordersController.updateOrder)
  .delete(ordersController.deleteOrder);

module.exports = router;
