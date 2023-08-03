const express = require('express');
const router = express.Router();
const productsController = require('../controllers/productsController');
const verifyJWT = require('../middlewares/verifyJWT');

router.use(verifyJWT);

router.route('/count').get(productsController.getCount);

router.route('/:categoryId').get(productsController.getProductsByCategoryId);

router.route('/').get(productsController.getAllProducts);

router
  .route('/')
  .post(productsController.createNewProduct)
  .patch(productsController.updateProduct)
  .delete(productsController.deleteProduct);

module.exports = router;
